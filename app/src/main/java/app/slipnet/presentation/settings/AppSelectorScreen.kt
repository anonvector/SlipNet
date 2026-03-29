package app.slipnet.presentation.settings

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppSelectorScreen(
    onNavigateBack: () -> Unit,
    viewModel: AppSelectorViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val listState = rememberLazyListState()
    val coroutineScope = rememberCoroutineScope()
    var showSearch by remember { mutableStateOf(false) }
    val searchFocusRequester = remember { FocusRequester() }

    LaunchedEffect(showSearch) {
        if (showSearch) {
            searchFocusRequester.requestFocus()
        }
    }

    BackHandler(enabled = showSearch) {
        showSearch = false
        viewModel.updateSearchQuery("")
    }

    Scaffold(
        topBar = {
            if (showSearch) {
                TopAppBar(
                    title = {
                        TextField(
                            value = uiState.searchQuery,
                            onValueChange = { viewModel.updateSearchQuery(it) },
                            placeholder = { Text("Search apps...") },
                            singleLine = true,
                            colors = TextFieldDefaults.colors(
                                focusedContainerColor = Color.Transparent,
                                unfocusedContainerColor = Color.Transparent,
                                focusedIndicatorColor = Color.Transparent,
                                unfocusedIndicatorColor = Color.Transparent
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .focusRequester(searchFocusRequester)
                        )
                    },
                    navigationIcon = {
                        IconButton(onClick = {
                            showSearch = false
                            viewModel.updateSearchQuery("")
                        }) {
                            Icon(Icons.Default.Close, contentDescription = "Close search")
                        }
                    }
                )
            } else {
                TopAppBar(
                    title = { Text("Select Apps") },
                    navigationIcon = {
                        IconButton(onClick = onNavigateBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                        }
                    },
                    actions = {
                        IconButton(onClick = { showSearch = true }) {
                            Icon(Icons.Default.Search, contentDescription = "Search")
                        }
                    }
                )
            }
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            // Filter chips row
            Row(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(
                    selected = uiState.showSelectedOnly,
                    onClick = { viewModel.toggleSelectedOnly() },
                    label = { Text("Selected") }
                )
                FilterChip(
                    selected = !uiState.showSystemApps,
                    onClick = { viewModel.toggleSystemApps() },
                    label = { Text("Hide system") }
                )
                Spacer(modifier = Modifier.weight(1f))
                Text(
                    text = "${uiState.selectedApps.size} selected",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (uiState.isLoading) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            } else {
                val isSearching = uiState.searchQuery.isNotBlank()

                // Build the grouped list: selected apps first, then alphabetical sections
                val selectedAppsSet = uiState.selectedApps
                val selectedGroup = if (!isSearching && !uiState.showSelectedOnly) {
                    uiState.apps.filter { it.packageName in selectedAppsSet }
                } else {
                    emptyList()
                }
                val remainingApps = if (!isSearching && !uiState.showSelectedOnly) {
                    uiState.apps.filter { it.packageName !in selectedAppsSet }
                } else {
                    uiState.apps
                }

                // Group remaining by first letter (only A-Z, everything else → #)
                val grouped = remainingApps.groupBy { app ->
                    val first = app.appName.firstOrNull()?.uppercaseChar() ?: '#'
                    if (first in 'A'..'Z') first.toString() else "#"
                }
                val sortedLetters = grouped.keys.sortedWith(compareBy { if (it == "#") "ZZZ" else it })

                // Build flat list items for the LazyColumn
                val listItems = buildList<AppListEntry> {
                    if (selectedGroup.isNotEmpty()) {
                        add(AppListEntry.SectionHeader("Selected"))
                        selectedGroup.forEach { add(AppListEntry.AppItem(it)) }
                    }
                    for (letter in sortedLetters) {
                        add(AppListEntry.SectionHeader(letter))
                        grouped[letter]!!.forEach { add(AppListEntry.AppItem(it)) }
                    }
                }

                // Compute letter-to-index mapping for the fast scroll rail
                val letterIndexMap = remember(listItems) {
                    val map = mutableMapOf<String, Int>()
                    listItems.forEachIndexed { index, entry ->
                        if (entry is AppListEntry.SectionHeader && entry.title.length == 1) {
                            map[entry.title] = index
                        }
                    }
                    map
                }
                val railLetters = remember(letterIndexMap) {
                    letterIndexMap.keys.sorted()
                }

                Box(modifier = Modifier.fillMaxSize()) {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(end = if (railLetters.size > 1 && !isSearching) 24.dp else 0.dp)
                    ) {
                        items(
                            count = listItems.size,
                            key = { index ->
                                when (val item = listItems[index]) {
                                    is AppListEntry.SectionHeader -> "header_${item.title}"
                                    is AppListEntry.AppItem -> item.app.packageName
                                }
                            }
                        ) { index ->
                            when (val item = listItems[index]) {
                                is AppListEntry.SectionHeader -> {
                                    SectionHeader(title = item.title)
                                }
                                is AppListEntry.AppItem -> {
                                    AppListItem(
                                        app = item.app,
                                        isSelected = item.app.packageName in selectedAppsSet,
                                        onToggle = { viewModel.toggleApp(item.app.packageName) }
                                    )
                                }
                            }
                        }
                    }

                    // Alphabet fast-scroll rail
                    if (railLetters.size > 1 && !isSearching) {
                        AlphabetRail(
                            letters = railLetters,
                            onLetterSelected = { letter ->
                                val targetIndex = letterIndexMap[letter] ?: return@AlphabetRail
                                coroutineScope.launch {
                                    listState.scrollToItem(targetIndex)
                                }
                            },
                            modifier = Modifier.align(Alignment.CenterEnd)
                        )
                    }
                }
            }
        }
    }
}

private sealed interface AppListEntry {
    data class SectionHeader(val title: String) : AppListEntry
    data class AppItem(val app: InstalledApp) : AppListEntry
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = 16.dp, vertical = 6.dp)
    )
}

@Composable
private fun AlphabetRail(
    letters: List<String>,
    onLetterSelected: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val density = LocalDensity.current
    var railHeightPx by remember { mutableStateOf(0f) }

    Column(
        modifier = modifier
            .fillMaxHeight()
            .width(24.dp)
            .padding(vertical = 8.dp)
            .onGloballyPositioned { coordinates ->
                railHeightPx = coordinates.size.height.toFloat()
            }
            .pointerInput(letters) {
                detectTapGestures { offset ->
                    if (railHeightPx > 0 && letters.isNotEmpty()) {
                        val index = ((offset.y / railHeightPx) * letters.size)
                            .toInt()
                            .coerceIn(0, letters.size - 1)
                        onLetterSelected(letters[index])
                    }
                }
            }
            .pointerInput(letters) {
                detectVerticalDragGestures { change, _ ->
                    change.consume()
                    if (railHeightPx > 0 && letters.isNotEmpty()) {
                        val index = ((change.position.y / railHeightPx) * letters.size)
                            .toInt()
                            .coerceIn(0, letters.size - 1)
                        onLetterSelected(letters[index])
                    }
                }
            },
        verticalArrangement = Arrangement.SpaceEvenly,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        letters.forEach { letter ->
            Text(
                text = letter,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Medium
                ),
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun drawableToBitmap(drawable: Drawable): Bitmap {
    if (drawable is BitmapDrawable && drawable.bitmap != null) {
        return drawable.bitmap
    }
    val width = if (drawable.intrinsicWidth > 0) drawable.intrinsicWidth else 48
    val height = if (drawable.intrinsicHeight > 0) drawable.intrinsicHeight else 48
    val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
    val canvas = Canvas(bitmap)
    drawable.setBounds(0, 0, canvas.width, canvas.height)
    drawable.draw(canvas)
    return bitmap
}

@Composable
private fun AppListItem(
    app: InstalledApp,
    isSelected: Boolean,
    onToggle: () -> Unit
) {
    val context = LocalContext.current
    val iconBitmap = remember(app.packageName) {
        try {
            val drawable = context.packageManager.getApplicationIcon(app.packageName)
            drawableToBitmap(drawable).asImageBitmap()
        } catch (_: Exception) {
            null
        }
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onToggle() }
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (iconBitmap != null) {
            Image(
                bitmap = iconBitmap,
                contentDescription = null,
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(8.dp))
            )
        } else {
            Box(modifier = Modifier.size(40.dp))
        }

        Spacer(modifier = Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = app.appName,
                style = MaterialTheme.typography.bodyLarge
            )
            Text(
                text = app.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Checkbox(
            checked = isSelected,
            onCheckedChange = { onToggle() }
        )
    }
}
