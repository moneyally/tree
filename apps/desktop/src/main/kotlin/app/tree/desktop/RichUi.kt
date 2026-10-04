package app.tree.desktop

import app.tree.shared.*

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.NewStickerItem

/** Decodes an image; null for bytes that are not one. */
private fun bitmap(bytes: ByteArray?): ImageBitmap? = try {
    bytes?.let { org.jetbrains.skia.Image.makeFromEncoded(it).toComposeImageBitmap() }
} catch (e: Exception) {
    null
}

/** A round photo, or the first letter of the name when there is none. */
@Composable
fun PhotoBadge(photo: ByteArray?, name: String, size: Int = 28) {
    val img = remember(photo) { bitmap(photo) }
    val m = Modifier.size(size.dp).clip(CircleShape)
    if (img != null) Image(img, name, m)
    else Box(m.background(MaterialTheme.colorScheme.secondaryContainer), contentAlignment = Alignment.Center) {
        Text(name.take(1).uppercase(), style = MaterialTheme.typography.bodySmall)
    }
}

/** The chat list / header photo: the other person's photo of a 1:1 chat. */
@Composable
fun ChatPhoto(model: AppModel, chat: Chat, size: Int = 28) {
    val rich by model.rich.state.collectAsState()
    PhotoBadge(rich.chatPhotos[chat.id]?.bytes, chat.title, size)
}

/** Messages the rich-chat parts draw themselves (stickers, places, events, video notes). */
fun isRich(state: UiState, m: Message): Boolean =
    !m.deleted && (m.kind in setOf("sticker", "location", "event") || (m.kind == "file" && state.files[m.id]?.videoNote == true))

private fun time(secs: Long): String =
    java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").format(java.time.Instant.ofEpochSecond(secs).atZone(java.time.ZoneId.systemDefault()))

/** A sticker, place, event or video note in the message list. */
@Composable
fun RichMessage(model: AppModel, state: UiState, chat: Chat, m: Message, who: String) {
    val rich by model.rich.state.collectAsState()
    val scope = rememberCoroutineScope()
    Column(Modifier.padding(4.dp)) {
        Text(who, style = MaterialTheme.typography.bodySmall)
        when (m.kind) {
            "sticker" -> {
                val ref = rich.stickers[m.id]
                val img by produceState<ImageBitmap?>(null, ref) { value = ref?.let { bitmap(model.rich.stickerImage(it.pack, it.index.toInt())) } }
                img?.let { Image(it, m.text ?: Strings.t("sticker"), Modifier.size(96.dp)) } ?: Text("${Strings.t("sticker")} ${m.text ?: ""}")
            }
            "location" -> rich.places[m.id]?.let { p ->
                // Ticks once a second while live, so the countdown moves and
                // an expired live location stops showing as live.
                var now by remember { mutableStateOf(System.currentTimeMillis() / 1000) }
                if (p.live) LaunchedEffect(m.id) { while (true) { delay(1000); now = System.currentTimeMillis() / 1000 } }
                val left = model.rich.countdown(p, now)
                Column(Modifier.background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp)).padding(8.dp)) {
                    Text("📍 " + (p.label ?: Strings.t(if (p.liveUntil != null) "live_location" else "location")))
                    Text("%.5f, %.5f".format(p.lat, p.lon) + (p.accuracyM?.let { " (±$it m)" } ?: ""), style = MaterialTheme.typography.bodySmall)
                    if (left != null) Text("${Strings.t("live_location")} · $left ${Strings.t("live_left")}", style = MaterialTheme.typography.bodySmall)
                    else if (p.ended) Text(Strings.t("live_ended"), style = MaterialTheme.typography.bodySmall)
                    if (rich.relays.map) {
                        val tile by produceState<ImageBitmap?>(null, p.lat, p.lon) { value = bitmap(model.rich.mapTile(p.lat, p.lon)) }
                        tile?.let { Image(it, Strings.t("location"), Modifier.size(128.dp)) }
                    }
                    Row {
                        TextButton(onClick = { runCatching { java.awt.Desktop.getDesktop().browse(java.net.URI(p.geoUri)) } }) { Text(Strings.t("open_maps")) }
                        if (left != null && m.id in rich.sharing) {
                            TextButton(onClick = { scope.launch { model.rich.stopLive(chat.id, m.id) } }) { Text(Strings.t("stop_sharing")) }
                        }
                    }
                }
            }
            "event" -> rich.events[m.id]?.let { e ->
                Column(Modifier.background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp)).padding(8.dp)) {
                    Text("📅 " + e.title + if (e.cancelled) " (${Strings.t("event_cancelled")})" else "")
                    Text(time(e.startsAt) + (e.endsAt?.let { " – " + time(it) } ?: ""), style = MaterialTheme.typography.bodySmall)
                    e.place?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                    e.description?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                    Text("${Strings.t("going")} ${e.going.size} · ${Strings.t("maybe")} ${e.maybe.size} · ${Strings.t("not")} ${e.not.size}",
                        style = MaterialTheme.typography.bodySmall)
                    if (!e.cancelled) Row {
                        listOf("going", "maybe", "not").forEach { a ->
                            TextButton(onClick = { scope.launch { model.rich.rsvp(chat.id, e.id, a) } }) {
                                Text(if (e.mine == a) "[${Strings.t(a)}]" else Strings.t(a))
                            }
                        }
                        if (e.creator == model.session?.memberId()) {
                            TextButton(onClick = { scope.launch { model.rich.cancelEvent(chat.id, e.id) } }) { Text(Strings.t("cancel_event")) }
                        }
                    }
                }
            }
            // Desktop playback is a placeholder: the note is saved and played elsewhere.
            else -> Text("⏺ " + Strings.t("video_note_play") + (state.files[m.id]?.durationMs?.let { " · ${it.toLong() / 1000}s" } ?: ""))
        }
    }
}

/** Buttons under the message field: stickers, GIF (hidden without a relay), location, event, video note. */
@Composable
fun RichComposer(model: AppModel, state: UiState, chat: Chat) {
    val rich by model.rich.state.collectAsState()
    val scope = rememberCoroutineScope()
    var panel by remember(chat.id) { mutableStateOf<String?>(null) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        val buttons = buildList {
            if (model.rich.allowed(state, "chat.stickers")) add("stickers")
            if (model.rich.gifAvailable(state)) add("gif")
            if (model.rich.allowed(state, "chat.location")) add("location")
            if (model.rich.allowed(state, "chat.events")) add("event")
            if (model.rich.allowed(state, "chat.video_notes") && model.rich.allowed(state, "chat.media")) add("video_note")
        }
        buttons.forEach { k -> TextButton(onClick = { panel = if (panel == k) null else k }) { Text(if (panel == k) "[${Strings.t(k)}]" else Strings.t(k)) } }
    }
    when (panel) {
        "stickers" -> StickerPanel(model, chat)
        "gif" -> {
            var q by remember { mutableStateOf("") }
            Text(Strings.t("gif_note"), style = MaterialTheme.typography.bodySmall)
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(q, { q = it }, label = { Text(Strings.t("gif_search")) }, singleLine = true)
                TextButton(onClick = { scope.launch { model.rich.searchGifs(q) } }) { Text("→") }
            }
            Row {
                rich.gifs.take(8).forEach { g ->
                    val img by produceState<ImageBitmap?>(null, g.media) { value = bitmap(model.rich.gifPreview(g)) }
                    Box(Modifier.padding(2.dp).clickable { scope.launch { if (model.rich.sendGif(chat.id, g)) panel = null } }) {
                        img?.let { Image(it, g.title, Modifier.size(72.dp)) } ?: Text(g.title.ifEmpty { "GIF" })
                    }
                }
            }
        }
        "location" -> {
            var lat by remember { mutableStateOf("") }
            var lon by remember { mutableStateOf("") }
            var label by remember { mutableStateOf("") }
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(lat, { lat = it }, label = { Text(Strings.t("latitude")) }, singleLine = true, modifier = Modifier.width(120.dp))
                OutlinedTextField(lon, { lon = it }, label = { Text(Strings.t("longitude")) }, singleLine = true, modifier = Modifier.width(120.dp))
                OutlinedTextField(label, { label = it }, label = { Text(Strings.t("label")) }, singleLine = true, modifier = Modifier.width(160.dp))
            }
            val la = lat.toDoubleOrNull()
            val lo = lon.toDoubleOrNull()
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(enabled = la != null && lo != null, onClick = { scope.launch { if (model.rich.sendLocation(chat.id, la!!, lo!!, null, label)) panel = null } }) {
                    Text(Strings.t("send_location"))
                }
                Text(" ${Strings.t("live_for")}:", style = MaterialTheme.typography.bodySmall)
                model.rich.liveChoices().forEach { secs ->
                    TextButton(enabled = la != null && lo != null, onClick = { scope.launch { if (model.rich.startLive(chat.id, la!!, lo!!, secs) != null) panel = null } }) {
                        Text(if (secs >= 3600) "${secs / 3600}h" else "${secs / 60}m")
                    }
                }
            }
        }
        "event" -> {
            var title by remember { mutableStateOf("") }
            var at by remember { mutableStateOf("") }
            var place by remember { mutableStateOf("") }
            var desc by remember { mutableStateOf("") }
            val starts = runCatching {
                java.time.LocalDateTime.parse(at.trim().replace(' ', 'T')).atZone(java.time.ZoneId.systemDefault()).toEpochSecond()
            }.getOrNull()
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(title, { title = it }, label = { Text(Strings.t("event_title")) }, singleLine = true, modifier = Modifier.width(160.dp))
                OutlinedTextField(at, { at = it }, label = { Text(Strings.t("event_time")) }, singleLine = true, modifier = Modifier.width(190.dp))
                OutlinedTextField(place, { place = it }, label = { Text(Strings.t("event_place")) }, singleLine = true, modifier = Modifier.width(140.dp))
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(desc, { desc = it }, label = { Text(Strings.t("event_description")) }, modifier = Modifier.width(320.dp))
                Button(enabled = title.isNotBlank() && starts != null, onClick = {
                    scope.launch { if (model.rich.createEvent(chat.id, title, starts!!, place, desc) != null) panel = null }
                }) { Text(Strings.t("new_event")) }
            }
        }
        "video_note" -> {
            // Recording on desktop: attach a short square video file.
            var secs by remember { mutableStateOf("10") }
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(secs, { secs = it }, label = { Text("s") }, singleLine = true, modifier = Modifier.width(70.dp))
                TextButton(onClick = {
                    val d = java.awt.FileDialog(null as java.awt.Frame?, Strings.t("video_note_send"), java.awt.FileDialog.LOAD)
                    d.isVisible = true
                    if (d.file != null) scope.launch {
                        val f = java.io.File(d.directory, d.file)
                        val mime = java.nio.file.Files.probeContentType(f.toPath()) ?: "video/mp4"
                        if (model.rich.sendVideoNote(chat.id, f.readBytes(), mime, (secs.toLongOrNull() ?: 10) * 1000)) panel = null
                    }
                }) { Text(Strings.t("video_note_send")) }
            }
        }
    }
}

/** Installed packs (click a sticker to send it), install by link, make a pack. */
@Composable
private fun StickerPanel(model: AppModel, chat: Chat) {
    val rich by model.rich.state.collectAsState()
    val scope = rememberCoroutineScope()
    var link by remember { mutableStateOf("") }
    var title by remember { mutableStateOf("") }
    var made by remember { mutableStateOf<String?>(null) }
    rich.packs.forEach { p ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(p.title, style = MaterialTheme.typography.bodySmall)
            p.items.forEachIndexed { i, item ->
                val img by produceState<ImageBitmap?>(null, p.id, i) { value = bitmap(model.rich.stickerImage(p.id, i)) }
                Box(Modifier.padding(2.dp).clickable { scope.launch { model.rich.sendSticker(chat.id, p.id, i) } }) {
                    img?.let { Image(it, item.name, Modifier.size(48.dp)) } ?: Text(item.emoji)
                }
            }
            TextButton(onClick = { scope.launch { model.rich.removePack(p.id) } }) { Text(Strings.t("remove_pack")) }
        }
        SelectionContainerText(p.link)
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(link, { link = it }, label = { Text(Strings.t("sticker_link")) }, singleLine = true)
        TextButton(onClick = { scope.launch { if (model.rich.installPack(link)) link = "" } }) { Text(Strings.t("install_pack")) }
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(title, { title = it }, label = { Text(Strings.t("pack_title")) }, singleLine = true)
        TextButton(onClick = {
            val d = java.awt.FileDialog(null as java.awt.Frame?, Strings.t("new_pack"), java.awt.FileDialog.LOAD)
            d.isMultipleMode = true
            d.isVisible = true
            val files = d.files.toList()
            if (files.isNotEmpty()) scope.launch {
                val items = files.map { f ->
                    NewStickerItem(f.nameWithoutExtension, "🙂", java.nio.file.Files.probeContentType(f.toPath()) ?: "image/png", f.readBytes())
                }
                made = model.rich.createPack(title.ifBlank { "Stickers" }, items)
            }
        }) { Text(Strings.t("new_pack")) }
    }
    made?.let { SelectionContainerText(it) }
}

@Composable
private fun SelectionContainerText(s: String) {
    androidx.compose.foundation.text.selection.SelectionContainer { Text(s, style = MaterialTheme.typography.bodySmall) }
}

/** Chat settings: this user's name for this chat only (user.per_chat_profile). */
@Composable
fun ChatProfilePanel(model: AppModel, group: String) {
    val rich by model.rich.state.collectAsState()
    val scope = rememberCoroutineScope()
    var name by remember(group) { mutableStateOf(rich.chatProfile?.name ?: "") }
    Text(Strings.t("chat_name"), style = MaterialTheme.typography.titleSmall)
    Text(Strings.t("chat_name_note"), style = MaterialTheme.typography.bodySmall)
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(name, { name = it }, label = { Text(Strings.t("chat_name")) }, singleLine = true)
        TextButton(onClick = { scope.launch { model.rich.setChatName(group, name) } }) { Text("✓") }
        if (rich.chatProfile != null) TextButton(onClick = { scope.launch { model.rich.clearChatProfile(group); name = "" } }) { Text(Strings.t("clear_chat_name")) }
    }
}

/** Settings: the profile photo (shared as user.profile_photo_visibility says). */
@Composable
fun ProfilePhotoPanel(model: AppModel, state: UiState) {
    val rich by model.rich.state.collectAsState()
    val scope = rememberCoroutineScope()
    Row(verticalAlignment = Alignment.CenterVertically) {
        PhotoBadge(rich.myPhoto?.bytes, state.name, 40)
        Text(" " + Strings.t("profile_photo"))
        TextButton(onClick = {
            val d = java.awt.FileDialog(null as java.awt.Frame?, Strings.t("set_photo"), java.awt.FileDialog.LOAD)
            d.isVisible = true
            if (d.file != null) scope.launch {
                val f = java.io.File(d.directory, d.file)
                model.rich.setPhoto(f.readBytes(), java.nio.file.Files.probeContentType(f.toPath()) ?: "image/jpeg")
            }
        }) { Text(Strings.t("set_photo")) }
        if (rich.myPhoto != null) TextButton(onClick = { scope.launch { model.rich.removePhoto() } }) { Text(Strings.t("remove_photo")) }
    }
}
