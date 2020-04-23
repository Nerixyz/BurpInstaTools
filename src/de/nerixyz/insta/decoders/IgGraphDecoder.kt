package de.nerixyz.insta.decoders

import burp.IRequestInfo
import de.nerixyz.insta.*

class IgGraphDecoder : MessageDecoder("graph.instagram.com") {
    override fun onRequest(request: IRequestInfo, rawData: ByteArray): String? {
        if (request.contentType == IRequestInfo.CONTENT_TYPE_MULTIPART) {
            val cmsgParam = request.parameters.findBodyParam("cmsg") ?: return "Could not find 'cmsg'"
            return rawData.copyOfRange(cmsgParam.valueStart, cmsgParam.valueEnd)
                    .inflate(true)
                    .utf8()
                    .jsonPrettyPrint()
        } else {
            val messageParam = request.parameters.findBodyParam("message") ?: return "Could not find 'message'"
            return rawData.copyOfRange(messageParam.valueStart, messageParam.valueEnd)
                    .utf8()
                    .urlDecode()
                    .base64Decode()
                    .inflate(false)
                    .utf8()
                    .jsonPrettyPrint()
        }
    }
}