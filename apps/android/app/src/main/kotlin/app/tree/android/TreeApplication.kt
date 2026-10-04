package app.tree.android

import android.app.Application
import app.tree.shared.AppModel
import app.tree.shared.Lang
import app.tree.shared.Strings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

/**
 * Holds the one [AppModel] of the process, so the open profile survives the
 * activity being recreated, and a push wake-up arriving while the app is in
 * the background can sync with it ([Wake]). When the app lock closes the
 * profile, or the system ends the process, the database key is gone from
 * memory and a wake-up can only say that something arrived.
 */
class TreeApplication : Application() {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    val model: AppModel by lazy {
        AppModel(scope).also { m ->
            m.notifier = { title, text -> Notifier.show(this, title, text) }
        }
    }

    /** The profile on this device (one per installation). */
    val profile: String get() = filesDir.resolve("profile.db").path

    override fun onCreate() {
        super.onCreate()
        Strings.lang = if (resources.configuration.locales[0].language == "ko") Lang.KO else Lang.EN
        Notifier.channel(this)
    }
}
