package app.slipnet.presentation.navigation

import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavBackStackEntry
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import app.slipnet.presentation.home.HomeScreen
import app.slipnet.presentation.profiles.EditProfileScreen
import app.slipnet.presentation.profiles.ProfileListScreen
import app.slipnet.presentation.scanner.DnsScannerScreen
import app.slipnet.presentation.scanner.ScanResultsScreen
import app.slipnet.presentation.settings.SettingsScreen

@Composable
fun NavGraph(
    navController: NavHostController,
    modifier: Modifier = Modifier
) {
    NavHost(
        navController = navController,
        startDestination = NavRoutes.Home.route,
        modifier = modifier,
        enterTransition = { EnterTransition.None },
        exitTransition = { ExitTransition.None },
        popEnterTransition = { EnterTransition.None },
        popExitTransition = { ExitTransition.None }
    ) {
        composable(NavRoutes.Home.route) {
            HomeScreen(
                onNavigateToProfiles = {
                    navController.navigate(NavRoutes.Profiles.route)
                },
                onNavigateToSettings = {
                    navController.navigate(NavRoutes.Settings.route)
                }
            )
        }

        composable(NavRoutes.Profiles.route) {
            ProfileListScreen(
                onNavigateBack = {
                    navController.popBackStack()
                },
                onNavigateToAddProfile = {
                    navController.navigate(NavRoutes.AddProfile.route)
                },
                onNavigateToEditProfile = { profileId ->
                    navController.navigate(NavRoutes.EditProfile.createRoute(profileId))
                }
            )
        }

        composable(NavRoutes.AddProfile.route) { backStackEntry ->
            val selectedResolvers = backStackEntry.savedStateHandle
                .get<String>("selected_resolvers")

            EditProfileScreen(
                profileId = null,
                onNavigateBack = {
                    navController.popBackStack()
                },
                onNavigateToScanner = {
                    navController.navigate(NavRoutes.DnsScanner.createRoute())
                },
                selectedResolvers = selectedResolvers
            )
        }

        composable(
            route = NavRoutes.EditProfile.route,
            arguments = listOf(
                navArgument("profileId") { type = NavType.LongType }
            )
        ) { backStackEntry ->
            val profileId = backStackEntry.arguments?.getLong("profileId")
            val selectedResolvers = backStackEntry.savedStateHandle
                .get<String>("selected_resolvers")

            EditProfileScreen(
                profileId = profileId,
                onNavigateBack = {
                    navController.popBackStack()
                },
                onNavigateToScanner = {
                    navController.navigate(NavRoutes.DnsScanner.createRoute(profileId))
                },
                selectedResolvers = selectedResolvers
            )
        }

        composable(NavRoutes.Settings.route) {
            SettingsScreen(
                onNavigateBack = {
                    navController.popBackStack()
                },
                onNavigateToScanner = {
                    navController.navigate(NavRoutes.DnsScanner.createRoute())
                }
            )
        }

        composable(
            route = NavRoutes.DnsScanner.route,
            arguments = listOf(
                navArgument("profileId") {
                    type = NavType.LongType
                    defaultValue = -1L
                }
            )
        ) { backStackEntry ->
            val profileId = backStackEntry.arguments?.getLong("profileId")?.takeIf { it != -1L }
            DnsScannerScreen(
                profileId = profileId,
                onNavigateBack = {
                    navController.popBackStack()
                },
                onNavigateToResults = {
                    navController.navigate(NavRoutes.ScanResults.createRoute(profileId))
                },
                onResolversSelected = { resolvers ->
                    // Pass selected resolvers back through saved state
                    navController.previousBackStackEntry?.savedStateHandle?.set("selected_resolvers", resolvers)
                }
            )
        }

        composable(
            route = NavRoutes.ScanResults.route,
            arguments = listOf(
                navArgument("profileId") {
                    type = NavType.LongType
                    defaultValue = -1L
                }
            )
        ) { backStackEntry ->
            val profileId = backStackEntry.arguments?.getLong("profileId")?.takeIf { it != -1L }
            // Get the parent (DnsScanner) back stack entry to share ViewModel
            val parentEntry = navController.getBackStackEntry(NavRoutes.DnsScanner.route)
            ScanResultsScreen(
                profileId = profileId,
                parentBackStackEntry = parentEntry,
                onNavigateBack = {
                    navController.popBackStack()
                },
                onResolversSelected = { resolvers ->
                    // Pass selected resolvers back through saved state and pop to scanner
                    navController.previousBackStackEntry?.savedStateHandle?.set("selected_resolvers", resolvers)
                }
            )
        }
    }
}
