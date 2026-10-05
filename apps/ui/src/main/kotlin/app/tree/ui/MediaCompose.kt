package app.tree.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.BarChart
import androidx.compose.material.icons.rounded.Event
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.InsertDriveFile
import androidx.compose.material.icons.rounded.LocationOn
import androidx.compose.material.icons.rounded.Remove
import androidx.compose.material.icons.rounded.Timer
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.Chat
import app.tree.shared.RichState
import app.tree.shared.UiState
import app.tree.shared.createPoll
import kotlinx.coroutines.launch
import uniffi.tree_ffi.ChatEventInfo
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.Place
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId

/** What the attach button offers, as a grid of tiles; each only where the chat allows it. */
@Composable
fun AttachSheet(model: AppModel, platform: TreePlatform, state: UiState, chat: Chat, onClose: () -> Unit) {
    var poll by remember { mutableStateOf(false) }
    var event by remember { mutableStateOf(false) }
    var place by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val allowed = { key: String -> state.chatFeatures.none { it.key == key && !it.applied } }
    val tiles = buildList {
        if (allowed("chat.media")) add(Triple(Icons.Rounded.Image, t("사진", "Photo"), TreeColors.TileBlue) to { platform.pickAndSend(chat.id, AttachKind.PHOTO); onClose() })
        if (allowed("chat.media") && allowed("chat.view_once")) add(Triple(Icons.Rounded.Visibility, t("한 번 보기", "View once"), TreeColors.TileViolet) to { platform.pickAndSend(chat.id, AttachKind.PHOTO_ONCE); onClose() })
        if (allowed("chat.media")) add(Triple(Icons.Rounded.InsertDriveFile, t("파일", "File"), TreeColors.TileSky) to { platform.pickAndSend(chat.id, AttachKind.FILE); onClose() })
        if (allowed("chat.polls")) add(Triple(Icons.Rounded.BarChart, t("투표", "Poll"), TreeColors.TileAmber) to { poll = true })
        if (allowed("chat.events")) add(Triple(Icons.Rounded.Event, t("일정", "Event"), TreeColors.TileRed) to { event = true })
        if (allowed("chat.location") && platform.hasLocation) add(Triple(Icons.Rounded.LocationOn, t("위치", "Location"), TreeColors.TileGreen) to { place = true })
    }
    Column(Modifier.fillMaxWidth().padding(12.dp)) {
        tiles.chunked(4).forEach { row ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                row.forEach { (look, action) ->
                    val (icon, label, color) = look
                    Column(
                        Modifier.weight(1f).clip(RoundedCornerShape(16.dp)).clickable(onClick = action).padding(vertical = 10.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Box(Modifier.size(52.dp).clip(CircleShape).background(color), contentAlignment = Alignment.Center) {
                            Icon(icon, null, tint = Color.White, modifier = Modifier.size(26.dp))
                        }
                        Spacer(Modifier.height(6.dp))
                        Text(label, style = MaterialTheme.typography.labelMedium)
                    }
                }
                repeat(4 - row.size) { Spacer(Modifier.weight(1f)) }
            }
        }
    }
    if (poll) PollDialog(model, chat) { poll = false; onClose() }
    if (event) EventDialog(model, chat) { event = false; onClose() }
    if (place) PlaceDialog(model, platform, chat) { place = false; onClose() }
}

/** Send where I am now, or share it live for a while (updated while the app is open). */
@Composable
private fun PlaceDialog(model: AppModel, platform: TreePlatform, chat: Chat, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    fun withFix(then: suspend (Triple<Double, Double, Int?>) -> Unit) = platform.currentLocation { at ->
        if (at == null) { model.notice(t("위치를 알 수 없어요", "Location unavailable")); onDone() }
        else scope.launch { then(at); onDone() }
    }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(t("위치 보내기", "Send location")) },
        text = {
            Column {
                Text(t("지금 위치", "Current location"), style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable { withFix { model.rich.sendLocation(chat.id, it.first, it.second, it.third) } }.padding(vertical = 14.dp, horizontal = 6.dp))
                model.rich.liveChoices().forEach { secs ->
                    val label = if (secs < 3600) t("실시간 ${secs / 60}분", "Live for ${secs / 60} min") else t("실시간 ${secs / 3600}시간", "Live for ${secs / 3600} h")
                    Text(label, style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable { withFix { model.rich.startLive(chat.id, it.first, it.second, secs) } }.padding(vertical = 14.dp, horizontal = 6.dp))
                }
                Text(t("실시간 위치는 앱이 열려 있는 동안 갱신돼요.", "Live location updates while the app is open."), style = MaterialTheme.typography.bodySmall, color = extra.muted)
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDone) { Text(t("취소", "Cancel")) } },
    )
}

/** While this device shares a live location in [chat]: a bar to stop it, and fresh fixes every 30 s. */
@Composable
fun LiveShareBar(model: AppModel, platform: TreePlatform, media: RichState, chat: Chat) {
    val scope = rememberCoroutineScope()
    val mine = media.sharing.filter { id -> media.places[id]?.live == true }
    if (mine.isEmpty()) return
    androidx.compose.runtime.LaunchedEffect(mine) {
        while (true) {
            kotlinx.coroutines.delay(30_000)
            platform.currentLocation { at -> if (at != null) scope.launch { mine.forEach { model.rich.updateLive(chat.id, it, at.first, at.second) } } }
        }
    }
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 10.dp).clip(RoundedCornerShape(18.dp)).background(extra.floating).padding(horizontal = 14.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Rounded.LocationOn, null, tint = TreeColors.TileGreen, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(t("내 위치를 실시간으로 공유 중", "Sharing your live location"), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Text(t("중지", "Stop"), color = extra.danger, style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.clip(RoundedCornerShape(8.dp)).clickable { scope.launch { mine.forEach { model.rich.stopLive(chat.id, it) } } }.padding(6.dp))
    }
}

/** A new poll: question, 2 to 10 options, several answers, anonymous. */
@Composable
private fun PollDialog(model: AppModel, chat: Chat, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var question by remember { mutableStateOf("") }
    val options = remember { mutableStateListOf("", "") }
    var multi by remember { mutableStateOf(false) }
    var anon by remember { mutableStateOf(false) }
    val ok = question.isNotBlank() && options.count { it.isNotBlank() } >= 2
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(t("투표 만들기", "New poll")) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(question, { question = it.take(300) }, placeholder = { Text(t("질문", "Question")) }, shape = RoundedCornerShape(14.dp), modifier = Modifier.fillMaxWidth())
                options.forEachIndexed { i, o ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(o, { options[i] = it.take(100) }, placeholder = { Text(t("선택지 ${i + 1}", "Option ${i + 1}")) }, singleLine = true, shape = RoundedCornerShape(14.dp), modifier = Modifier.weight(1f))
                        if (options.size > 2) IconButton(onClick = { options.removeAt(i) }) { Icon(Icons.Rounded.Remove, t("빼기", "Remove"), tint = extra.muted) }
                    }
                }
                if (options.size < 10) TextButton(onClick = { options.add("") }) {
                    Icon(Icons.Rounded.Add, null, modifier = Modifier.size(18.dp)); Spacer(Modifier.width(6.dp)); Text(t("선택지 추가", "Add option"))
                }
                SwitchRow(t("여러 개 고르기", "Several answers"), null, multi) { multi = it }
                SwitchRow(t("누가 골랐는지 숨기기", "Anonymous"), null, anon) { anon = it }
            }
        },
        confirmButton = { TextButton(onClick = { scope.launch { model.createPoll(chat.id, question.trim(), options.map { it.trim() }, multi, anon); onDone() } }, enabled = ok) { Text(t("보내기", "Send"), fontWeight = FontWeight.SemiBold) } },
        dismissButton = { TextButton(onClick = onDone) { Text(t("취소", "Cancel")) } },
    )
}

/** A new event: title, day, time, place. */
@Composable
private fun EventDialog(model: AppModel, chat: Chat, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    val zone = ZoneId.systemDefault()
    var title by remember { mutableStateOf("") }
    var place by remember { mutableStateOf("") }
    var day by remember { mutableStateOf(LocalDate.now(zone).plusDays(1)) }
    var hour by remember { mutableStateOf(19) }
    var minute by remember { mutableStateOf(0) }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(t("일정 만들기", "New event")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(title, { title = it.take(200) }, placeholder = { Text(t("무엇을 하나요", "What")) }, singleLine = true, shape = RoundedCornerShape(14.dp))
                Stepper(Format.day(day.atStartOfDay(zone).toEpochSecond()) + " (" + listOf("월", "화", "수", "목", "금", "토", "일")[day.dayOfWeek.value - 1] + ")",
                    { if (day.isAfter(LocalDate.now(zone))) day = day.minusDays(1) }, { day = day.plusDays(1) })
                Stepper(Format.clock(LocalDateTime.of(day, java.time.LocalTime.of(hour, minute)).atZone(zone).toEpochSecond()),
                    { val m = hour * 60 + minute - 30; if (m >= 0) { hour = m / 60; minute = m % 60 } },
                    { val m = hour * 60 + minute + 30; if (m < 24 * 60) { hour = m / 60; minute = m % 60 } })
                OutlinedTextField(place, { place = it.take(200) }, placeholder = { Text(t("장소 (선택)", "Place (optional)")) }, singleLine = true, shape = RoundedCornerShape(14.dp))
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val at = LocalDateTime.of(day, java.time.LocalTime.of(hour, minute)).atZone(zone).toEpochSecond()
                scope.launch { model.rich.createEvent(chat.id, title.trim(), at, place.trim().ifBlank { null }); onDone() }
            }, enabled = title.isNotBlank()) { Text(t("보내기", "Send"), fontWeight = FontWeight.SemiBold) }
        },
        dismissButton = { TextButton(onClick = onDone) { Text(t("취소", "Cancel")) } },
    )
}

@Composable
private fun Stepper(label: String, onMinus: () -> Unit, onPlus: () -> Unit) {
    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(extra.card), verticalAlignment = Alignment.CenterVertically) {
        IconButton(onClick = onMinus) { Icon(Icons.Rounded.Remove, t("앞으로", "Earlier")) }
        Text(label, Modifier.weight(1f), textAlign = TextAlign.Center, style = MaterialTheme.typography.titleSmall)
        IconButton(onClick = onPlus) { Icon(Icons.Rounded.Add, t("뒤로", "Later")) }
    }
}

/** A place in a bubble: the map tile through the server's relay when it has one, else the coordinates. */
@Composable
fun LocationContent(model: AppModel, platform: TreePlatform, media: RichState, m: Message, textColor: Color) {
    val p: Place = media.places[m.id] ?: run { Text(Format.preview(m), color = textColor); return }
    val tile by produceState<androidx.compose.ui.graphics.ImageBitmap?>(null, p.lat, p.lon, media.relays.map) {
        value = if (media.relays.map) model.rich.mapTile(p.lat, p.lon)?.let { platform.decodeImage(it, 512) } else null
    }
    Column(Modifier.widthIn(max = 260.dp)) {
        Box(Modifier.size(240.dp, 130.dp).clip(RoundedCornerShape(12.dp)).background(extra.divider), contentAlignment = Alignment.Center) {
            tile?.let { Image(it, null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop) }
            Icon(Icons.Rounded.LocationOn, null, tint = TreeColors.TileRed, modifier = Modifier.size(36.dp))
        }
        Spacer(Modifier.height(6.dp))
        Text(p.label ?: t("위치", "Location"), color = textColor, style = MaterialTheme.typography.titleSmall)
        val sub = when {
            p.live -> model.rich.countdown(p)?.let { t("실시간 · $it 남음", "Live · $it left") } ?: t("실시간", "Live")
            p.ended -> t("실시간 공유 끝남", "Live sharing ended")
            else -> "%.5f, %.5f".format(p.lat, p.lon)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (p.live) { Icon(Icons.Rounded.Timer, null, tint = extra.bubbleMeta, modifier = Modifier.size(14.dp)); Spacer(Modifier.width(4.dp)) }
            Text(sub, color = extra.bubbleMeta, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** An event in a bubble: when and where, and going / maybe / not. */
@Composable
fun EventContent(model: AppModel, chat: Chat, media: RichState, m: Message, textColor: Color) {
    val scope = rememberCoroutineScope()
    val e: ChatEventInfo = media.events[m.id] ?: run { Text(Format.preview(m), color = textColor); return }
    Column(Modifier.widthIn(min = 220.dp, max = 280.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(40.dp).clip(RoundedCornerShape(10.dp)).background(TreeColors.TileRed), contentAlignment = Alignment.Center) {
                val d = Instant.ofEpochSecond(e.startsAt).atZone(ZoneId.systemDefault())
                Text("${d.monthValue}/${d.dayOfMonth}", color = Color.White, style = MaterialTheme.typography.labelLarge)
            }
            Spacer(Modifier.width(10.dp))
            Column {
                Text(e.title, color = textColor, style = MaterialTheme.typography.titleSmall, textDecoration = if (e.cancelled) androidx.compose.ui.text.style.TextDecoration.LineThrough else null)
                Text(Format.listTime(e.startsAt) + " " + Format.clock(e.startsAt) + (e.place?.let { " · $it" } ?: ""), color = extra.bubbleMeta, style = MaterialTheme.typography.bodySmall)
            }
        }
        if (e.cancelled) Text(t("취소된 일정", "Cancelled"), color = extra.danger, style = MaterialTheme.typography.labelMedium)
        else Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf("going" to t("참석", "Going") + " ${e.going.size}", "maybe" to t("미정", "Maybe") + " ${e.maybe.size}", "not" to t("불참", "Can't") + " ${e.not.size}").forEach { (k, label) ->
                val on = e.mine == k
                Text(label, style = MaterialTheme.typography.labelMedium,
                    color = if (on) MaterialTheme.colorScheme.onPrimary else textColor,
                    modifier = Modifier.clip(RoundedCornerShape(12.dp)).background(if (on) MaterialTheme.colorScheme.primary else textColor.copy(alpha = 0.10f))
                        .clickable { scope.launch { model.rich.rsvp(chat.id, e.id, k) } }.padding(horizontal = 10.dp, vertical = 6.dp))
            }
        }
    }
}

/** A view-once picture: opened full screen once; afterwards only the line that it was opened. */
@Composable
fun ViewOnceContent(model: AppModel, platform: TreePlatform, m: Message, mine: Boolean, textColor: Color) {
    val scope = rememberCoroutineScope()
    var showing by remember { mutableStateOf<androidx.compose.ui.graphics.ImageBitmap?>(null) }
    val f = m.file
    Row(
        Modifier.clip(RoundedCornerShape(12.dp)).clickable(enabled = f != null && !mine) {
            scope.launch { model.fileBytes(m.id)?.let { showing = platform.decodeImage(it, 2048) } }
        }.padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(40.dp).clip(CircleShape).background(TreeColors.TileViolet), contentAlignment = Alignment.Center) {
            Icon(Icons.Rounded.Visibility, null, tint = Color.White)
        }
        Spacer(Modifier.width(10.dp))
        Text(
            when { mine -> t("한 번 보기 사진", "View-once photo"); f == null -> t("열어 본 사진", "Opened"); else -> t("한 번 보기 사진 · 눌러서 보기", "View-once photo · tap to open") },
            color = textColor, style = MaterialTheme.typography.bodyMedium,
        )
    }
    showing?.let { img ->
        AlertDialog(
            onDismissRequest = { showing = null; scope.launch { model.refresh() } },
            text = { Image(img, null, Modifier.fillMaxWidth(), contentScale = ContentScale.Fit) },
            confirmButton = { TextButton(onClick = { showing = null; scope.launch { model.refresh() } }) { Text(t("닫기", "Close")) } },
        )
    }
}
