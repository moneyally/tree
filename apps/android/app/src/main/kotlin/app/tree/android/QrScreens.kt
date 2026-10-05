package app.tree.android

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import app.tree.shared.AppModel
import app.tree.shared.LinkUi
import app.tree.shared.ScanOutcome
import app.tree.shared.Strings
import app.tree.shared.qr.CodeKind
import app.tree.shared.qr.QrMatrix
import kotlinx.coroutines.launch
import java.util.concurrent.Executors

/** A QR code drawn module by module, black on white whatever the theme. */
@Composable
fun QrImage(m: QrMatrix, size: Dp) {
    Canvas(Modifier.size(size).background(Color.White)) {
        val cell = this.size.minDimension / m.size
        for (y in 0 until m.size) for (x in 0 until m.size) {
            if (m[x, y]) drawRect(Color.Black, Offset(x * cell, y * cell), Size(cell + 0.5f, cell + 0.5f))
        }
    }
}

/** The QR code with its text below and a copy button (the text is the code's content, exactly). */
@Composable
fun QrWithText(m: QrMatrix?, text: String, size: Dp = 300.dp) {
    val clipboard = LocalClipboardManager.current
    var copied by remember(text) { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        m?.let { QrImage(it, size) }
        SelectionContainer { Text(text, style = MaterialTheme.typography.bodySmall) }
        TextButton(onClick = { clipboard.setText(AnnotatedString(text)); copied = true }) {
            Text(Strings.t(if (copied) "qr_copied" else "qr_copy"))
        }
    }
}

/**
 * The steps of a device link on either device: the QR code (new device),
 * then the six digits, large, with one clear "match" and one "different /
 * I did not start this" (which cancels). Nothing links until both devices
 * confirm (PROTOCOL.md 8.11).
 */
@Composable
fun LinkSteps(model: AppModel, link: LinkUi, newDevice: Boolean) {
    val scope = rememberCoroutineScope()
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when (link.state) {
            "waiting" -> {
                link.text?.let {
                    Text(Strings.t("qr_show_new"), textAlign = TextAlign.Center)
                    QrWithText(link.qr, it)
                }
                Text(Strings.t("link_wait"), style = MaterialTheme.typography.bodySmall)
            }
            "code" -> {
                Text(Strings.t("code_title"), style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
                BigCode(link.code)
                Text(Strings.t("code_hold_both"), textAlign = TextAlign.Center, fontWeight = FontWeight.Bold)
                Button(
                    onClick = { scope.launch { if (newDevice) model.confirmNewDevice(true) else model.confirmLink(true) } },
                    modifier = Modifier.fillMaxWidth().height(64.dp),
                ) { Text(Strings.t("code_match"), fontSize = 18.sp) }
                OutlinedButton(
                    onClick = { scope.launch { if (newDevice) model.confirmNewDevice(false) else model.confirmLink(false) } },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(Strings.t("code_differ")) }
            }
            "confirmed" -> {
                BigCode(link.code)
                Text(Strings.t("code_other_too"), textAlign = TextAlign.Center)
                Text(Strings.t("link_wait"), style = MaterialTheme.typography.bodySmall)
            }
            "linked" -> Text(Strings.t("link_done"), style = MaterialTheme.typography.titleLarge)
            else -> Text(Strings.t("link_cancelled") + (link.reason?.let { ": $it" } ?: ""), style = MaterialTheme.typography.titleMedium)
        }
    }
}

@Composable
private fun BigCode(code: String?) {
    Text(code ?: "", fontSize = 52.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, letterSpacing = 4.sp)
}

/** Full screen while this signed-in device links another one. */
@Composable
fun LinkInProgressScreen(model: AppModel, link: LinkUi) {
    val ends = link.state != "code" && link.state != "confirmed"
    if (ends) BackHandler { model.closeLink() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        LinkSteps(model, link, newDevice = false)
        // While the digits are shown the person answers with one of the two buttons.
        if (ends) TextButton(onClick = model::closeLink) { Text(Strings.t("qr_close")) }
    }
}

/**
 * The camera scanner for [want] (a new device's link, or a friend's
 * username link), with a paste field as fallback. Asks for the camera
 * permission with an explanation first; without it only the paste field
 * works. Frames are decoded on the phone with ZXing; texts other than the
 * expected Tree code are ignored with a message and never opened.
 */
@Composable
fun ScanScreen(model: AppModel, want: CodeKind, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    BackHandler(onBack = onClose)
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var denied by remember { mutableStateOf(false) }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok -> granted = ok; denied = !ok }
    var message by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var torch by remember { mutableStateOf(false) }
    var hasTorch by remember { mutableStateOf(false) }
    var pasted by remember { mutableStateOf("") }
    // A code the server refused (an expired link, say) is not sent again
    // for every camera frame that still shows it.
    var refused by remember { mutableStateOf<String?>(null) }

    fun use(text: String, fromCamera: Boolean) {
        if (busy || (fromCamera && text == refused)) return
        busy = true
        scope.launch {
            val o = model.useScanned(text, want)
            if (o == ScanOutcome.ACCEPTED) onClose() else {
                message = AppModel.scanMessage(o, want)
                refused = text
            }
            busy = false
        }
    }

    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().verticalScroll(rememberScrollState())) {
      app.tree.ui.BackHeader(Strings.t(if (want == CodeKind.DEVICE_LINK) "qr_link_new_device" else "qr_add_friend"), onClose)
      Column(Modifier.padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text(Strings.t(if (want == CodeKind.DEVICE_LINK) "qr_scan_device" else "qr_scan_friend"), color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (granted) {
            CameraScanner(
                torch = torch,
                onTorch = { hasTorch = it },
                onText = { text ->
                    when (val d = ScanFrames.decide(text, want)) {
                        is ScanFrames.Decision.Use -> use(d.text, fromCamera = true)
                        is ScanFrames.Decision.Ignore -> message = Strings.t(d.messageKey)
                    }
                },
            )
            if (hasTorch) TextButton(onClick = { torch = !torch }) { Text(Strings.t("qr_torch") + if (torch) " ✓" else "") }
        } else {
            Text(Strings.t(if (denied) "qr_camera_denied" else "qr_camera_why"))
            if (!denied) Button(onClick = { ask.launch(Manifest.permission.CAMERA) }) { Text(Strings.t("qr_camera_allow")) }
        }
        message?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        // Fallback: the link text, copied from the other device or a message.
        Text(Strings.t("qr_paste"), style = MaterialTheme.typography.bodySmall)
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(pasted, { pasted = it; message = null }, singleLine = true, modifier = Modifier.weight(1f))
            TextButton(onClick = { use(pasted, fromCamera = false) }) { Text("→") }
        }
      }
    }
}

/** Camera preview with frame analysis (CameraX); [onText] gets every decoded text on the main thread. */
@Composable
private fun CameraScanner(torch: Boolean, onTorch: (Boolean) -> Unit, onText: (String) -> Unit) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val latest by rememberUpdatedState(onText)
    val view = remember { PreviewView(context) }
    var camera by remember { mutableStateOf<Camera?>(null) }
    DisposableEffect(owner) {
        val worker = Executors.newSingleThreadExecutor()
        val main = ContextCompat.getMainExecutor(context)
        val future = ProcessCameraProvider.getInstance(context)
        var disposed = false
        future.addListener({
            if (disposed) return@addListener
            val provider = future.get()
            val preview = Preview.Builder().build().also { it.setSurfaceProvider(view.surfaceProvider) }
            val analysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
            analysis.setAnalyzer(worker) { image ->
                try {
                    // The Y plane (luminance) is all a QR code needs.
                    val plane = image.planes[0]
                    val buf = plane.buffer
                    val bytes = ByteArray(buf.remaining()).also { buf.get(it) }
                    ScanFrames.read(bytes, image.width, image.height, plane.rowStride)?.let { t ->
                        main.execute { if (!disposed) latest(t) }
                    }
                } finally {
                    image.close()
                }
            }
            provider.unbindAll()
            val c = provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            camera = c
            onTorch(c.cameraInfo.hasFlashUnit())
        }, main)
        onDispose {
            disposed = true
            if (future.isDone) future.get().unbindAll()
            worker.shutdown()
            camera = null
        }
    }
    LaunchedEffect(torch, camera) { camera?.cameraControl?.enableTorch(torch) }
    androidx.compose.foundation.layout.Box(Modifier.fillMaxWidth().aspectRatio(3f / 4f).clip(androidx.compose.foundation.shape.RoundedCornerShape(28.dp))) {
        AndroidView({ view }, Modifier.fillMaxSize())
        // The square to put the code in: four bright corners.
        val accent = MaterialTheme.colorScheme.primary
        androidx.compose.foundation.Canvas(Modifier.fillMaxSize()) {
            val side = size.minDimension * 0.62f
            val l = (size.width - side) / 2
            val t = (size.height - side) / 2
            val arm = side * 0.16f
            val w = 5.dp.toPx()
            val cap = androidx.compose.ui.graphics.StrokeCap.Round
            for ((x, y, dx, dy) in listOf(listOf(l, t, 1f, 1f), listOf(l + side, t, -1f, 1f), listOf(l, t + side, 1f, -1f), listOf(l + side, t + side, -1f, -1f))) {
                drawLine(accent, androidx.compose.ui.geometry.Offset(x, y), androidx.compose.ui.geometry.Offset(x + arm * dx, y), w, cap)
                drawLine(accent, androidx.compose.ui.geometry.Offset(x, y), androidx.compose.ui.geometry.Offset(x, y + arm * dy), w, cap)
            }
        }
    }
}

/** Settings: my username, my QR code (with the link and a copy button), and the two scanners. */
@Composable
fun QrSettings(model: AppModel, onScan: (CodeKind) -> Unit) {
    val scope = rememberCoroutineScope()
    val state by model.state.collectAsState()
    var username by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { model.loadUsernameLink() }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(username, { username = it }, label = { Text(Strings.t("username")) }, singleLine = true, modifier = Modifier.weight(1f))
            TextButton(onClick = { scope.launch { model.setUsername(username) } }) { Text("✓") }
        }
        // user.username_link (in the list below) turns the link on.
        state.usernameLink?.let { l ->
            Text(Strings.t("qr_my_code"), style = MaterialTheme.typography.titleSmall)
            QrWithText(state.usernameQr, l, 240.dp)
            TextButton(onClick = { scope.launch { model.resetUsernameLink() } }) { Text(Strings.t("reset_link")) }
        }
        Button(onClick = { onScan(CodeKind.USERNAME) }, modifier = Modifier.fillMaxWidth()) { Text(Strings.t("qr_add_friend")) }
        Button(onClick = { onScan(CodeKind.DEVICE_LINK) }, modifier = Modifier.fillMaxWidth()) { Text(Strings.t("qr_link_new_device")) }
    }
}
