package de.nerixyz.insta

import burp.*
import de.nerixyz.insta.decoders.MessageDecoder
import java.awt.Component
import java.awt.GridLayout
import java.io.PrintStream
import java.net.URL
import javax.swing.JPanel

class IgMessageTab internal constructor(private val controller: IMessageEditorController,
                                        private val editable: Boolean,
                                        private val callbacks: IBurpExtenderCallbacks,
                                        private val helpers: IExtensionHelpers,
                                        private val decoders: List<MessageDecoder>
) : IMessageEditorTab {

    private val tabComponent: JPanel = JPanel(GridLayout())
    private var textEditor: ITextEditor? = null
    private var message: ByteArray? = null

    override fun getTabCaption(): String = "Instagram"
    override fun getUiComponent(): Component = tabComponent
    override fun getMessage(): ByteArray = message!!
    override fun isModified(): Boolean = false
    override fun getSelectedData(): ByteArray = ByteArray(0)

    private fun setText(content: String?) {
        assertOrCreateTextEditor()
        textEditor!!.setEditable(editable)
        textEditor!!.text = content?.toByteArray()
        tabComponent.repaint()
    }

    override fun isEnabled(content: ByteArray, isRequest: Boolean): Boolean {
        try {
            val httpService = controller.httpService
            val url = if (isRequest) {
                helpers.analyzeRequest(httpService, content).url ?: URL("http", "unknown", "unknown")
            } else {
                val response = helpers.analyzeResponse(content)
                return response.inferredMimeType == "JSON"
            }
            return decoders.stream().anyMatch { it.match(url) }
        } catch (e: Exception) {
            e.printStackTrace(PrintStream(callbacks.stderr))
            PrintStream(callbacks.stdout).println("Exception thrown in isEnabled() - ${e.message}")
        }
        return false
    }

    override fun setMessage(content: ByteArray?, isRequest: Boolean) {
        var url = "<unknown>"
        try {
            if (content == null) {
                setText("No content/message.")
                return
            }
            if (isRequest) {
                val requestInfo = helpers.analyzeRequest(controller.httpService, content)
                url = requestInfo.url.toString()
                val decoder = decoders.stream().filter { it.match(requestInfo.url) }.findFirst().orElse(null)
                if (decoder == null) {
                    setText("No decoder.")
                } else {
                    setText(decoder.onRequest(requestInfo, content))
                }
            } else {
                setText(helpers.analyzeResponse(content).jsonPrettyPrint(content))
            }
        } catch (e: Exception) {
            e.printStackTrace(PrintStream(callbacks.stderr))
            PrintStream(callbacks.stdout).println("Exception thrown in setMessage() URL: $url - ${e.message}")
        }
    }

    private fun assertOrCreateTextEditor() {
        if (textEditor == null) {
            val textEditor = callbacks.createTextEditor()
            tabComponent.add(textEditor.component)
            this.textEditor = textEditor
        }
    }
}