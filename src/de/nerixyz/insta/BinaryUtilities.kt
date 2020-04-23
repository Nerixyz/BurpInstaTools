package de.nerixyz.insta

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.*
import java.util.zip.DataFormatException
import java.util.zip.Inflater
import kotlin.math.min

@Throws(DataFormatException::class)
fun ByteArray.inflate(raw: Boolean): ByteArray {
    val inflater = Inflater(raw)
    inflater.setInput(this)
    val buffers = ArrayList<ByteArray>()
    var len = 0
    while (inflater.remaining > 0) {
        val current = ByteArray(1024)
        len += inflater.inflate(current)
        buffers.add(current)
    }
    val finalBuf = ByteArray(len)
    var offset = 0
    for (buffer in buffers) {
        val copyLen = min(len - offset, buffer.size)
        System.arraycopy(buffer, 0, finalBuf, offset, copyLen)
        offset += copyLen
    }
    return finalBuf
}

fun String.urlDecode(): String = URLDecoder.decode(this, StandardCharsets.UTF_8)
fun String.base64Decode(): ByteArray = Base64.getDecoder().decode(this.toByteArray())

fun ByteArray.utf8(): String = String(this, StandardCharsets.UTF_8)