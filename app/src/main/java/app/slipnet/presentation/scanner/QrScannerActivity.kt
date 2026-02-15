package app.slipnet.presentation.scanner

import android.content.Intent
import android.graphics.BitmapFactory
import android.widget.ImageButton
import android.widget.Toast
import app.slipnet.R
import com.google.zxing.BinaryBitmap
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.client.android.Intents
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.DecoratedBarcodeView

class QrScannerActivity : CaptureActivity() {

    companion object {
        private const val REQUEST_GALLERY = 1001
    }

    override fun initializeContent(): DecoratedBarcodeView {
        setContentView(R.layout.activity_qr_scanner)

        findViewById<ImageButton>(R.id.btn_gallery).setOnClickListener {
            val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                type = "image/*"
            }
            startActivityForResult(intent, REQUEST_GALLERY)
        }

        return findViewById(R.id.barcode_scanner)
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_GALLERY) {
            if (resultCode != RESULT_OK || data?.data == null) return
            decodeQrFromUri(data.data!!)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    private fun decodeQrFromUri(uri: android.net.Uri) {
        try {
            val inputStream = contentResolver.openInputStream(uri)
                ?: throw Exception("Cannot open image")
            val bitmap = BitmapFactory.decodeStream(inputStream)
            inputStream.close()
            if (bitmap == null) throw Exception("Cannot decode image")

            val width = bitmap.width
            val height = bitmap.height
            val pixels = IntArray(width * height)
            bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
            bitmap.recycle()

            val source = RGBLuminanceSource(width, height, pixels)
            val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
            val result = QRCodeReader().decode(binaryBitmap)

            val intent = Intent().apply {
                putExtra(Intents.Scan.RESULT, result.text)
            }
            setResult(RESULT_OK, intent)
            finish()
        } catch (_: com.google.zxing.NotFoundException) {
            Toast.makeText(this, "No QR code found in image", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Error reading image: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
}
