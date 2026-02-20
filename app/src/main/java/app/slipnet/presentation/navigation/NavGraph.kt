package app.slipnet.presentation.navigation

import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import app.slipnet.presentation.main.MainScreen
import app.slipnet.presentation.profiles.EditProfileScreen
import app.slipnet.presentation.scanner.DnsScannerScreen
import app.slipnet.presentation.scanner.ScanResultsScreen
import app.slipnet.presentation.settings.AppSelectorScreen
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
            MainScreen(
                onNavigateToAddProfile = { tunnelType ->
                    navController.navigate(NavRoutes.AddProfile.createRoute(tunnelType))
                },
                onNavigateToEditProfile = { profileId ->
                    navController.navigate(NavRoutes.EditProfile.createRoute(profileId))
                },
                onNavigateToSettings = {
                    navController.navigate(NavRoutes.Settings.route)
                }
            )
        }

        composable(
            route = NavRoutes.AddProfile.route,
            arguments = listOf(
                navArgument("tunnelType") { type = NavType.StringType }
            )
        ) { backStackEntry ->
            val selectedResolvers = backStackEntry.savedStateHandle
                .get<String>("selected_resolvers")

            EditProfileScreen(
                profileId = null,
                onNavigateBack = {
                    navController.popBackStack()
                },
                onNavigateToScanner = {
                    navController.navigate(NavRoutes.DnsScanner.createRoute(fromProfile = true))
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
                    navController.navigate(NavRoutes.DnsScanner.createRoute(profileId, fromProfile = true))
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
                },
                onNavigateToAppSelector = {
                    navController.navigate(NavRoutes.AppSelector.route)
                }
            )
        }

        composable(NavRoutes.AppSelector.route) {
            AppSelectorScreen(
                onNavigateBack = {
                    navController.popBackStack()
                }
            )
        }

        composable(
            route = NavRoutes.DnsScanner.route,
            arguments = listOf(
                navArgument("profileId") {
                    type = NavType.LongType
                    defaultValue = -1L
                },
                navArgument("fromProfile") {
                    type = NavType.BoolType
                    defaultValue = false
                }
            )
        ) { backStackEntry ->
            val profileId = backStackEntry.arguments?.getLong("profileId")?.takeIf { it != -1L }
            val fromProfile = backStackEntry.arguments?.getBoolean("fromProfile") ?: false
            DnsScannerScreen(
                profileId = profileId,
                onNavigateBack = {
                    navController.popBackStack()
                },
                onNavigateToResults = {
                    navController.navigate(NavRoutes.ScanResults.createRoute(profileId, fromProfile))
                },
                onResolversSelected = { resolvers ->
                    val profileRoute = if (profileId != null) {
                        NavRoutes.EditProfile.createRoute(profileId)
                    } else if (fromProfile) {
                        NavRoutes.AddProfile.route
                    } else {
                        null
                    }
                    if (profileRoute != null) {
                        navController.getBackStackEntry(profileRoute).savedStateHandle["selected_resolvers"] = resolvers
                        navController.popBackStack(profileRoute, inclusive = false)
                    } else {
                        navController.popBackStack()
                    }
                }
            )
        }

        composable(
            route = NavRoutes.ScanResults.route,
            arguments = listOf(
                navArgument("profileId") {
                    type = NavType.LongType
                    defaultValue = -1L
                },
                navArgument("fromProfile") {
                    type = NavType.BoolType
                    defaultValue = false
                }
            )
        ) { backStackEntry ->
            val profileId = backStackEntry.arguments?.getLong("profileId")?.takeIf { it != -1L }
            val fromProfile = backStackEntry.arguments?.getBoolean("fromProfile") ?: false
            val parentEntry = remember { navController.getBackStackEntry(NavRoutes.DnsScanner.route) }
            ScanResultsScreen(
                profileId = profileId,
                fromProfile = fromProfile,
                parentBackStackEntry = parentEntry,
                onNavigateBack = {
                    navController.popBackStack()
                },
                onResolversSelected = { resolvers ->
                    val profileRoute = if (profileId != null) {
                        NavRoutes.EditProfile.createRoute(profileId)
                    } else {
                        NavRoutes.AddProfile.route
                    }
                    navController.getBackStackEntry(profileRoute).savedStateHandle["selected_resolvers"] = resolvers
                    navController.popBackStack(profileRoute, inclusive = false)
                }
            )
        }
    }
}
