package burp;

import com.google.gson.*;

import javax.swing.*;
import java.awt.*;
import java.io.PrintStream;
import java.util.Arrays;

public class IgMessageTab implements IMessageEditorTab {

    private boolean editable;
    private JPanel tabComponent;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IMessageEditorController controller;

    private ITextEditor textEditor = null;

    private byte[] message = null;

    IgMessageTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.controller = controller;
        this.editable = editable;
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.tabComponent = new JPanel(new GridLayout());
    }

    @Override
    public String getTabCaption() {
        return "Instagram";
    }

    @Override
    public Component getUiComponent() {
        return this.tabComponent;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        try {
            if (isRequest) {
                IHttpService service = null;
                try{
                    service = controller.getHttpService();
                }catch(Exception e) {
                    new PrintStream(callbacks.getStdout()).println("Exception thrown in getHttpService()");
                }
                IRequestInfo info = helpers.analyzeRequest(service, content);
                return info.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED && info.getUrl().getHost().equals("i.instagram.com");
            } else {
                IResponseInfo info = helpers.analyzeResponse(content);
                return info.getInferredMimeType().equals("JSON");
            }
        }catch(Exception e) {
            e.printStackTrace(new PrintStream(callbacks.getStderr()));
            new PrintStream(callbacks.getStdout()).println("Exception thrown in isEnabled()");
        }
        return false;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        try {
            this.message = content;
            if (content == null || content.length == 0) {
                return;
            }

            if (isRequest) {
                this.handleRequest(content, helpers.analyzeRequest(content));
            } else {
                this.handleResponse(content, helpers.analyzeResponse(content));
            }
            tabComponent.repaint();
        }catch (Exception e) {
            e.printStackTrace(new PrintStream(callbacks.getStderr()));
            new PrintStream(callbacks.getStdout()).println("Exception thrown in setMessage()");
        }
    }
    private void handleRequest(byte[] content, IRequestInfo request) {
        try {
            byte[] bodyData = Arrays.copyOfRange(content, request.getBodyOffset(), content.length);
            String[][] requestPairs = null;
            String signedBody = null;
            String signature = null;
            if (bodyData.length > 0) {
                requestPairs = decodeUrlEncodedRequest(new String(bodyData));
                if (requestPairs.length == 2) {
                    String[] pair = null;
                    for (var p : requestPairs) {
                        if (p[0].equals("signed_body"))
                            pair = p;
                    }
                    if (pair != null) {
                        signedBody = helpers.urlDecode(pair[1]);
                        int firstDot = signedBody.indexOf('.');
                        signature = signedBody.substring(0, firstDot);
                        signedBody = signedBody.substring(firstDot + 1);
                    }
                }
            }
            String json = "";
            var gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();
            if (signedBody != null) {
                json = signature + "\n" + gson.toJson(JsonParser.parseString(signedBody));

            } else if (requestPairs != null) {
                var obj = new JsonObject();
                for(var pair : requestPairs) {
                    obj.add(pair[0], new JsonPrimitive(pair[1]));
                }
                json = gson.toJson(obj);
            }
            assertOrCreateTextEditor();
            textEditor.setEditable(editable);
            textEditor.setText(json.getBytes());

        }catch(Exception e) {
            e.printStackTrace(new PrintStream(callbacks.getStderr()));
            new PrintStream(callbacks.getStdout()).println("Exception thrown in handleRequest()\n\tPath: " + request.getUrl().getPath());
        }
    }

    private void assertOrCreateTextEditor() {
        if(textEditor == null) {
            textEditor = callbacks.createTextEditor();
            tabComponent.add(textEditor.getComponent());
        }
    }

    private String[][] decodeUrlEncodedRequest(String body) {
        var encPairs = body.split("&");
        var reqData = new String[encPairs.length][2];
        int i = 0;
        for(var pair : encPairs) {
            var parts = pair.split("=");
            reqData[i] = parts;
            i++;
        }
        return reqData;
    }

    private void handleResponse(byte[] content, IResponseInfo response) {
        byte[] bodyData = Arrays.copyOfRange(content, response.getBodyOffset(), content.length);
        var gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();
        String json = gson.toJson(JsonParser.parseString(new String(bodyData)));
        assertOrCreateTextEditor();
        textEditor.setEditable(editable);
        textEditor.setText(json.getBytes());
    }

    @Override
    public byte[] getMessage() {
        return this.message;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return new byte[0];
    }
}

