package fr.aegis.android.security

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** Renders a signed AEGIS invitation as a QR bitmap for on-screen display. */
object PairingQrGenerator {
    fun generate(invitation: String, sizePx: Int = 1024): Bitmap {
        require(sizePx in 256..2048) { "Taille QR hors limites" }
        require(invitation.length <= 4096) { "Invitation trop volumineuse" }

        val hints = mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.Q,
            EncodeHintType.MARGIN to 2,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        val matrix = QRCodeWriter().encode(
            invitation,
            BarcodeFormat.QR_CODE,
            sizePx,
            sizePx,
            hints
        )
        val pixels = IntArray(sizePx * sizePx)
        for (y in 0 until sizePx) {
            for (x in 0 until sizePx) {
                pixels[y * sizePx + x] =
                    if (matrix[x, y]) COLOR_DARK else COLOR_LIGHT
            }
        }
        return Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888).apply {
            setPixels(pixels, 0, sizePx, 0, 0, sizePx, sizePx)
        }
    }

    private const val COLOR_DARK = 0xFF080C12.toInt()
    private const val COLOR_LIGHT = 0xFFFFFFFF.toInt()
}
