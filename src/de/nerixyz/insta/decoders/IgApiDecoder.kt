package de.nerixyz.insta.decoders

import burp.*
import de.nerixyz.insta.*
import java.net.URL

/**
 * match a Signature (hex.{data})
 */
private val SIGNATURE_REGEX = Regex("^([a-fA-F\\d]+|SIGNATURE)\\.(.+)\$")

/**
 * Decodes everything on i.instagram.com
 */
class IgApiDecoder : MessageDecoder("i.instagram.com") {
    // support both i.instagram and b.i.instagram
    override fun match(url: URL): Boolean = url.host.endsWith(domain)

    override fun onRequest(request: IRequestInfo, rawData: ByteArray): String? {
        var parameters = request.parameters
        if(request.headers.contains("Content-Encoding: gzip")) {
            parameters = rawData.sliceArray(request.bodyOffset..rawData.lastIndex)
                    .gzipDecode()
                    .utf8()
                    .split("&")
                    .map { val split = it.split("="); RequestParameter(split[0], split[1], IParameter.PARAM_BODY) }.toList()
        }
        val requestParts = arrayListOf<String>()
        if (request.bodyOffset < rawData.size - 1) {
            val signedInfo = parameters.findBodyParam("signed_body")
            if (signedInfo != null && SIGNATURE_REGEX.matches(signedInfo.value)) {
                val (signature, body) = SIGNATURE_REGEX.find(signedInfo.value)!!.destructured
                requestParts.add(signature.urlDecode())
                requestParts.add(body.urlDecode().jsonPrettyPrint())
            }
            requestParts.add(parameters.streamAllBodyParams().filter { it.name != "signed_body" }.toJson())
        } else {
            requestParts.add(parameters.streamAllUrlParams().toJson())
        }
        return requestParts.joinToString("\n")
    }
}

class RequestParameter constructor(private val name: String, private val value: String, private val type: Byte) : IParameter  {
    override fun getValueEnd(): Int = -1
    override fun getName(): String = this.name
    override fun getType(): Byte = this.type
    override fun getValue(): String = this.value
    override fun getNameStart(): Int = -1
    override fun getValueStart(): Int = -1
    override fun getNameEnd(): Int = -1
}