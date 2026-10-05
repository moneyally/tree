package app.tree.ui

import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import uniffi.tree_ffi.Message

/** Times as Korean apps write them: 오전 9:41 / 어제 / 10월 3일 / 2025. 10. 3. */
object Format {
    private val zone: ZoneId get() = ZoneId.systemDefault()

    fun clock(seconds: Long): String {
        val t = Instant.ofEpochSecond(seconds).atZone(zone)
        val h = t.hour
        val ampm = if (h < 12) "오전" else "오후"
        val h12 = if (h % 12 == 0) 12 else h % 12
        return "$ampm $h12:${t.minute.toString().padStart(2, '0')}"
    }

    /** Within this many seconds of their last "seen" someone counts as online. */
    const val ONLINE_S = 200L

    fun online(seen: app.tree.shared.Seen?, now: Long = System.currentTimeMillis() / 1000): Boolean =
        seen?.exact == true && seen.at != null && now - seen.at < ONLINE_S

    /**
     * "온라인", "3분 전 접속", "2시간 전 접속", "어제 오후 3:10 접속", a date;
     * vague when only their last message is known ("최근에 접속함").
     */
    fun seenLabel(seen: app.tree.shared.Seen?, now: Long = System.currentTimeMillis() / 1000): String {
        val at = seen?.at ?: return t("오래 전에 접속함", "Last seen a long time ago")
        val ago = (now - at).coerceAtLeast(0)
        if (!seen.exact) return when {
            ago < 3 * 86400 -> t("최근에 접속함", "Last seen recently")
            ago < 7 * 86400 -> t("이번 주에 접속함", "Last seen this week")
            ago < 30 * 86400 -> t("이번 달에 접속함", "Last seen this month")
            else -> t("오래 전에 접속함", "Last seen a long time ago")
        }
        val d = Instant.ofEpochSecond(at).atZone(zone).toLocalDate()
        val today = Instant.ofEpochSecond(now).atZone(zone).toLocalDate()
        return when {
            ago < ONLINE_S -> t("온라인", "online")
            ago < 3600 -> t("${ago / 60}분 전 접속", "last seen ${ago / 60} min ago")
            d == today -> t("${ago / 3600}시간 전 접속", "last seen ${ago / 3600} h ago")
            d == today.minusDays(1) -> t("어제 ${clock(at)} 접속", "last seen yesterday at ${clock(at)}")
            else -> t("${listTime(at, now)} 접속", "last seen ${listTime(at, now)}")
        }
    }

    /** For the chat list: today's time, 어제, a weekday this week, or a date. */
    fun listTime(seconds: Long, now: Long = System.currentTimeMillis() / 1000): String {
        if (seconds <= 0) return ""
        val d = Instant.ofEpochSecond(seconds).atZone(zone).toLocalDate()
        val today = Instant.ofEpochSecond(now).atZone(zone).toLocalDate()
        return when {
            d == today -> clock(seconds)
            d == today.minusDays(1) -> "어제"
            d.isAfter(today.minusDays(7)) -> listOf("월", "화", "수", "목", "금", "토", "일")[d.dayOfWeek.value - 1] + "요일"
            d.year == today.year -> "${d.monthValue}월 ${d.dayOfMonth}일"
            else -> "${d.year}. ${d.monthValue}. ${d.dayOfMonth}."
        }
    }

    /** Date separator inside a chat. */
    fun day(seconds: Long, now: Long = System.currentTimeMillis() / 1000): String {
        val d: LocalDate = Instant.ofEpochSecond(seconds).atZone(zone).toLocalDate()
        val today = Instant.ofEpochSecond(now).atZone(zone).toLocalDate()
        val wd = listOf("월", "화", "수", "목", "금", "토", "일")[d.dayOfWeek.value - 1]
        return when {
            d == today -> "오늘"
            d == today.minusDays(1) -> "어제"
            d.year == today.year -> "${d.monthValue}월 ${d.dayOfMonth}일 ${wd}요일"
            else -> "${d.year}년 ${d.monthValue}월 ${d.dayOfMonth}일 ${wd}요일"
        }
    }

    fun sameDay(a: Long, b: Long): Boolean =
        Instant.ofEpochSecond(a).atZone(zone).toLocalDate() == Instant.ofEpochSecond(b).atZone(zone).toLocalDate()

    /** One line about a message for the chat list. */
    fun preview(m: Message): String = when {
        m.deleted -> "삭제된 메시지"
        m.kind == "text" -> (m.text ?: "").replace('\n', ' ')
        m.kind == "file" -> when {
            m.file?.voice == true -> "🎤 음성 메시지"
            m.file?.videoNote == true -> "🎥 영상 메시지"
            m.file?.mime?.startsWith("image/") == true -> "📷 사진"
            m.file?.mime?.startsWith("video/") == true -> "🎬 동영상"
            else -> "📎 " + (m.file?.name ?: m.text ?: "파일")
        }
        m.kind == "sticker" -> "스티커"
        m.kind == "poll" -> "📊 투표" + (m.text?.let { ": $it" } ?: "")
        m.kind == "location" -> "📍 위치"
        m.kind == "event" -> "📅 일정" + (m.text?.let { ": $it" } ?: "")
        m.kind == "welcome" -> m.text ?: "환영합니다"
        m.kind == "left" -> "${m.who ?: "멤버"}님이 나갔습니다"
        m.kind == "removed" -> "${m.who ?: "멤버"}님이 내보내졌습니다"
        else -> m.text ?: ""
    }

    fun size(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        bytes < 1024L * 1024 * 1024 -> String.format("%.1f MB", bytes / 1048576.0)
        else -> String.format("%.2f GB", bytes / 1073741824.0)
    }
}
