package de.nerixyz.insta.decoders

import burp.IRequestInfo
import java.net.URL

abstract class MessageDecoder(var domain: String) {

    /**
     * Checks if this URL is valid
     * @param url
     * @param isRequest
     * @return Entry is valid
     */
    open fun match(url: URL): Boolean = url.host == domain

    /**
     * Turns this request into a String
     */
    abstract fun onRequest(request: IRequestInfo, rawData: ByteArray): String?
}
