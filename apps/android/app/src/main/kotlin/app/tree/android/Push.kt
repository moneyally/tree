package app.tree.android

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import app.tree.shared.Strings
import kotlinx.coroutines.launch

/**
 * Push wake-ups (PROTOCOL.md 8.8): the server sends the word `wake` to an
 * endpoint and never content. The endpoint comes from a push distributor
 * app installed on the phone, spoken to with the open distributor
 * broadcast protocol below (no vendor library). Without a distributor the
 * app falls back to a periodic job ([SyncJob], every 15 minutes at best,
 * as the system allows). Either way, a wake-up syncs only while the
 * profile is open in memory; while it is locked the app shows a
 * content-free "something arrived" notification.
 */
object Push {
    // The open push distributor protocol (connector side).
    private const val DIST_REGISTER = "org.unifiedpush.android.distributor.REGISTER"
    private const val DIST_UNREGISTER = "org.unifiedpush.android.distributor.UNREGISTER"
    const val NEW_ENDPOINT = "org.unifiedpush.android.connector.NEW_ENDPOINT"
    const val MESSAGE = "org.unifiedpush.android.connector.MESSAGE"
    const val UNREGISTERED = "org.unifiedpush.android.connector.UNREGISTERED"
    const val REGISTRATION_FAILED = "org.unifiedpush.android.connector.REGISTRATION_FAILED"

    private fun prefs(ctx: Context) = ctx.getSharedPreferences("push", Context.MODE_PRIVATE)

    /** The random token that ties the distributor's messages to this app's registration. */
    fun token(ctx: Context): String {
        val p = prefs(ctx)
        return p.getString("token", null) ?: java.util.UUID.randomUUID().toString().also { p.edit().putString("token", it).apply() }
    }

    fun endpoint(ctx: Context): String? = prefs(ctx).getString("endpoint", null)

    fun saveEndpoint(ctx: Context, endpoint: String?) = prefs(ctx).edit().putString("endpoint", endpoint).apply()

    /** Distributor apps installed on this phone (package names). */
    fun distributors(ctx: Context): List<String> =
        ctx.packageManager.queryBroadcastReceivers(Intent(DIST_REGISTER), 0).map { it.activityInfo.packageName }.distinct()

    /**
     * Asks the first distributor for an endpoint (the answer comes to
     * [PushReceiver]); without one, schedules the periodic job. Returns
     * whether a distributor was found.
     */
    fun register(ctx: Context): Boolean {
        val d = distributors(ctx).firstOrNull()
        if (d == null) {
            SyncJob.schedule(ctx)
            return false
        }
        val i = Intent(DIST_REGISTER).setPackage(d)
            .putExtra("token", token(ctx))
            .putExtra("application", ctx.packageName)
        // Identifies this app to distributors that check the sender.
        val pi = PendingIntent.getBroadcast(ctx, 0, Intent("app.tree.android.PUSH_ID"), PendingIntent.FLAG_IMMUTABLE)
        i.putExtra("pi", pi)
        ctx.sendBroadcast(i)
        return true
    }

    fun unregister(ctx: Context) {
        distributors(ctx).forEach { d -> ctx.sendBroadcast(Intent(DIST_UNREGISTER).setPackage(d).putExtra("token", token(ctx))) }
        saveEndpoint(ctx, null)
    }
}

/** Answers from the distributor: a new endpoint, a wake-up, an unregistration. */
class PushReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        // Only the distributor knows this app's token.
        if (intent.getStringExtra("token") != Push.token(ctx)) return
        val app = ctx.applicationContext as TreeApplication
        val pending = goAsync()
        app.scope.launch {
            try {
                when (intent.action) {
                    Push.NEW_ENDPOINT -> {
                        val endpoint = intent.getStringExtra("endpoint")
                        Push.saveEndpoint(ctx, endpoint)
                        app.model.device.registerPushEndpoint(endpoint)
                    }
                    Push.UNREGISTERED, Push.REGISTRATION_FAILED -> {
                        Push.saveEndpoint(ctx, null)
                        app.model.device.registerPushEndpoint(null)
                        SyncJob.schedule(ctx)
                    }
                    Push.MESSAGE -> Wake.handle(ctx)
                }
            } finally {
                pending.finish()
            }
        }
    }
}

/** What a wake-up does (push or periodic job). */
object Wake {
    suspend fun handle(ctx: Context) {
        val app = ctx.applicationContext as TreeApplication
        // Open profile: sync; the model notifies per message (mute, silent,
        // user.notification_content). Locked: only "something arrived".
        if (!app.model.device.onWake()) Notifier.locked(ctx)
    }
}

/** The fallback without a distributor: a periodic job while the app is installed. */
class SyncJob : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        val app = applicationContext as TreeApplication
        // Locked: there is nothing to read without the key, and no reason to
        // wake the user for a check that may have found nothing.
        if (app.model.session == null) return false
        app.scope.launch {
            try {
                app.model.device.onWake()
            } finally {
                jobFinished(params, false)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = true

    companion object {
        private const val ID = 4201

        fun schedule(ctx: Context) {
            val js = ctx.getSystemService(JobScheduler::class.java) ?: return
            if (js.getPendingJob(ID) != null) return
            js.schedule(
                JobInfo.Builder(ID, ComponentName(ctx, SyncJob::class.java))
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                    .setPeriodic(15 * 60 * 1000L)
                    .build(),
            )
        }
    }
}

/** Local notifications (the text only where the model allows it). */
object Notifier {
    private const val CHANNEL = "messages"

    fun channel(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(NotificationChannel(CHANNEL, Strings.t("notify_channel"), NotificationManager.IMPORTANCE_DEFAULT).apply {
            // The lock screen shows the notification without its text unless
            // the user allowed text (user.notification_content decides what is in it).
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        })
    }

    private fun allowed(ctx: Context): Boolean =
        Build.VERSION.SDK_INT < 33 || ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    fun show(ctx: Context, title: String, text: String?) {
        if (!allowed(ctx)) return
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        val open = PendingIntent.getActivity(ctx, 0, Intent(ctx, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(ctx, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle(title)
            .setContentIntent(open)
            .setAutoCancel(true)
        if (text != null) n.setContentText(text)
        nm.notify(title.hashCode(), n.build())
    }

    /** While the profile is locked: no name, no text. */
    fun locked(ctx: Context) = show(ctx, Strings.t("app"), Strings.t("notify_locked"))
}
