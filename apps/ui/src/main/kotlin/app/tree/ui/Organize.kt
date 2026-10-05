package app.tree.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CreateNewFolder
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.Chat
import app.tree.shared.UiState
import app.tree.shared.cancelScheduled
import app.tree.shared.remindMe
import app.tree.shared.schedule
import kotlinx.coroutines.launch
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.time.ZoneId

/** The person's own folders (not the built-in ones): what is in each, delete, make a new one. */
@Composable
fun FoldersCard(model: AppModel, state: UiState) {
    val scope = rememberCoroutineScope()
    var creating by remember { mutableStateOf(false) }
    val mine = state.folders.filter { it.kind == "user" }
    CardGroup(title = t("내 폴더", "My folders")) {
        mine.forEach { f ->
            SettingsRow(f.name, t("대화 ${f.chats.size}개", "${f.chats.size} chats"), Icons.Rounded.Folder, TreeColors.TileSky,
                trailing = { TextButton(onClick = { scope.launch { model.deleteFolder(f.name) } }) { Text(t("삭제", "Delete"), color = extra.danger) } })
        }
        SettingsRow(t("새 폴더", "New folder"), null, Icons.Rounded.CreateNewFolder, TreeColors.TileGreen, onClick = { creating = true }, trailing = null)
    }
    if (creating) {
        var name by remember { mutableStateOf("") }
        val picked = remember { mutableStateListOf<String>() }
        AlertDialog(
            onDismissRequest = { creating = false },
            title = { Text(t("새 폴더", "New folder")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(name, { name = it.take(32) }, placeholder = { Text(t("이름 (예: 회사, 가족)", "Name (e.g. Work, Family)")) }, singleLine = true, shape = RoundedCornerShape(14.dp))
                    LazyColumn(Modifier.heightIn(max = 300.dp)) {
                        items(state.chats.filter { it.status == "accepted" }, key = { it.id }) { c ->
                            Row(Modifier.fillMaxWidth().clickable { if (c.id in picked) picked.remove(c.id) else picked.add(c.id) }, verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(c.id in picked, { on -> if (on) picked.add(c.id) else picked.remove(c.id) })
                                Text(c.title, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    creating = false
                    scope.launch { if (model.createFolder(name.trim())) picked.forEach { model.fileChat(name.trim(), it) } }
                }, enabled = name.isNotBlank()) { Text(t("만들기", "Create"), fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { creating = false }) { Text(t("취소", "Cancel")) } },
        )
    }
}

/** Puts [chat] into folders or takes it out (check boxes). */
@Composable
fun FolderPickDialog(model: AppModel, state: UiState, chat: Chat, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    val mine = state.folders.filter { it.kind == "user" }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(t("폴더에 넣기", "Add to folder")) },
        text = {
            Column {
                if (mine.isEmpty()) Text(t("아직 폴더가 없어요. 설정 → 대화 폴더에서 만들어요.", "No folders yet. Make one in Settings → Chat folders."), color = extra.muted)
                mine.forEach { f ->
                    val inIt = chat.id in f.chats
                    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).clickable { scope.launch { model.fileChat(f.name, chat.id, !inIt) } }, verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(inIt, { on -> scope.launch { model.fileChat(f.name, chat.id, on) } })
                        Text(f.name)
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDone) { Text(t("완료", "Done")) } },
    )
}

/** Picks a moment: a day and a time in 15-minute steps, from now on. */
@Composable
fun WhenPicker(initial: LocalDateTime, onChange: (LocalDateTime) -> Unit) {
    val zone = ZoneId.systemDefault()
    var at by remember { mutableStateOf(initial) }
    fun set(v: LocalDateTime) { if (v.isAfter(LocalDateTime.now(zone))) { at = v; onChange(v) } }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        StepRow(Format.day(at.atZone(zone).toEpochSecond()) + " (" + listOf("월", "화", "수", "목", "금", "토", "일")[at.dayOfWeek.value - 1] + ")", { set(at.minusDays(1)) }, { set(at.plusDays(1)) })
        StepRow(Format.clock(at.atZone(zone).toEpochSecond()), { set(at.minusMinutes(15)) }, { set(at.plusMinutes(15)) })
    }
}

@Composable
private fun StepRow(label: String, minus: () -> Unit, plus: () -> Unit) {
    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        TextButton(onClick = minus) { Text("−", style = MaterialTheme.typography.titleLarge) }
        Text(label, Modifier.weight(1f), textAlign = androidx.compose.ui.text.style.TextAlign.Center, style = MaterialTheme.typography.titleSmall)
        TextButton(onClick = plus) { Text("+", style = MaterialTheme.typography.titleLarge) }
    }
}

private fun nextRound(minutesAhead: Long): LocalDateTime {
    val t0 = LocalDateTime.now().plusMinutes(minutesAhead)
    return t0.withSecond(0).withNano(0).withMinute((t0.minute / 15) * 15)
}

/** Send [text] later from this device (it goes when the app runs at that time). */
@Composable
fun ScheduleDialog(model: AppModel, chat: Chat, text: String, onDone: (Boolean) -> Unit) {
    val scope = rememberCoroutineScope()
    var at by remember { mutableStateOf(nextRound(60)) }
    AlertDialog(
        onDismissRequest = { onDone(false) },
        title = { Text(t("예약 보내기", "Schedule")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(text, maxLines = 2, overflow = TextOverflow.Ellipsis, color = extra.muted)
                WhenPicker(at) { at = it }
                Text(t("이 기기가 그 시간에 켜져 있으면 보내져요.", "Sent by this device when it is on at that time."), style = MaterialTheme.typography.bodySmall, color = extra.muted)
            }
        },
        confirmButton = {
            TextButton(onClick = {
                scope.launch { val ok = model.schedule(chat.id, text, at.atZone(ZoneId.systemDefault()).toEpochSecond()) != null; onDone(ok) }
            }) { Text(t("예약", "Schedule"), fontWeight = FontWeight.SemiBold) }
        },
        dismissButton = { TextButton(onClick = { onDone(false) }) { Text(t("취소", "Cancel")) } },
    )
}

/** The chat's scheduled messages, with cancel. */
@Composable
fun ScheduledBar(model: AppModel, state: UiState) {
    val scope = rememberCoroutineScope()
    val list = state.rich.scheduled
    var open by remember { mutableStateOf(false) }
    if (list.isEmpty()) return
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 10.dp).clip(RoundedCornerShape(18.dp))
            .background(extra.floating).clickable { open = true }.padding(horizontal = 14.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        androidx.compose.material3.Icon(Icons.Rounded.Schedule, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(end = 8.dp))
        Text(t("예약된 메시지 ${list.size}개", "${list.size} scheduled"), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
    }
    if (open) AlertDialog(
        onDismissRequest = { open = false },
        title = { Text(t("예약된 메시지", "Scheduled messages")) },
        text = {
            Column {
                list.sortedBy { it.at }.forEach { m ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(m.text, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            Text(Format.listTime(m.at) + " " + Format.clock(m.at), style = MaterialTheme.typography.bodySmall, color = extra.muted)
                        }
                        TextButton(onClick = { scope.launch { model.cancelScheduled(m.id) } }) { Text(t("취소", "Cancel"), color = extra.danger) }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { open = false }) { Text(t("닫기", "Close")) } },
    )
}

/** "Remind me" about a message: in an hour, this evening, tomorrow morning, or a chosen time. */
@Composable
fun RemindDialog(model: AppModel, chat: Chat, messageId: String, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    val zone = ZoneId.systemDefault()
    var custom by remember { mutableStateOf<LocalDateTime?>(null) }
    val evening = LocalDateTime.of(LocalDate.now(zone), LocalTime.of(21, 0)).let { if (it.isAfter(LocalDateTime.now(zone))) it else null }
    val choices = listOfNotNull(
        t("1시간 뒤", "In an hour") to LocalDateTime.now(zone).plusHours(1),
        evening?.let { t("오늘 밤 9시", "Tonight at 9") to it },
        t("내일 아침 9시", "Tomorrow at 9") to LocalDateTime.of(LocalDate.now(zone).plusDays(1), LocalTime.of(9, 0)),
    )
    fun remind(at: LocalDateTime) = scope.launch {
        if (model.remindMe(chat.id, messageId, at.atZone(zone).toEpochSecond()) != null) model.notice(t("알려 드릴게요", "Reminder set"))
        onDone()
    }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(t("나중에 알림", "Remind me")) },
        text = {
            Column {
                choices.forEach { (label, at) ->
                    Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable { remind(at) }.padding(vertical = 14.dp, horizontal = 6.dp))
                }
                if (custom == null) Text(t("시간 고르기", "Pick a time"), style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable { custom = nextRound(120) }.padding(vertical = 14.dp, horizontal = 6.dp))
                else WhenPicker(custom!!) { custom = it }
            }
        },
        confirmButton = { if (custom != null) TextButton(onClick = { remind(custom!!) }) { Text(t("설정", "Set"), fontWeight = FontWeight.SemiBold) } },
        dismissButton = { TextButton(onClick = onDone) { Text(t("취소", "Cancel")) } },
    )
}
