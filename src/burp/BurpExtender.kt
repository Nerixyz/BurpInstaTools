package burp

import de.nerixyz.insta.IgMessageTab
import de.nerixyz.insta.decoders.IgApiDecoder
import de.nerixyz.insta.decoders.IgGraphDecoder

class BurpExtender : IBurpExtender, IMessageEditorTabFactory {
    private var callbacks: IBurpExtenderCallbacks? = null
    private var helpers: IExtensionHelpers? = null
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers
        callbacks.setExtensionName("InstaTools")
        callbacks.registerMessageEditorTabFactory(this)
    }

    override fun createNewInstance(controller: IMessageEditorController, editable: Boolean): IMessageEditorTab {
        val callbacks = this.callbacks
        if (callbacks == null || callbacks.helpers == null) {
            throw IllegalStateException("Callbacks or helpers are null")
        }
        return IgMessageTab(controller, editable, callbacks, callbacks.helpers, arrayListOf(IgApiDecoder(), IgGraphDecoder()))
    }
}