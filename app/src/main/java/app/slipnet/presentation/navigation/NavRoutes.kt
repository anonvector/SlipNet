package app.slipnet.presentation.navigation

sealed class NavRoutes(val route: String) {
    data object Home : NavRoutes("home")
    data object Profiles : NavRoutes("profiles")
    data object AddProfile : NavRoutes("add_profile")
    data object EditProfile : NavRoutes("edit_profile/{profileId}") {
        fun createRoute(profileId: Long) = "edit_profile/$profileId"
    }
    data object Settings : NavRoutes("settings")
    data object DnsScanner : NavRoutes("dns_scanner?profileId={profileId}") {
        fun createRoute(profileId: Long? = null): String {
            return if (profileId != null) {
                "dns_scanner?profileId=$profileId"
            } else {
                "dns_scanner"
            }
        }
    }
    data object ScanResults : NavRoutes("scan_results?profileId={profileId}") {
        fun createRoute(profileId: Long? = null): String {
            return if (profileId != null) {
                "scan_results?profileId=$profileId"
            } else {
                "scan_results"
            }
        }
    }
}
