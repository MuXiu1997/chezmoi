package chezmoi

// FIXME implement externals in chezmoi source state format
// FIXME implement external git repos
// FIXME implement include and exclude entry type sets for externals

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/coreos/go-semver/semver"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	vfs "github.com/twpayne/go-vfs/v4"
	"go.uber.org/multierr"
)

// An ExternalType is a type of external source.
type ExternalType string

// ExternalTypes.
const (
	ExternalTypeArchive ExternalType = "archive"
	ExternalTypeFile    ExternalType = "file"
)

// An External is an external source.
type External struct {
	Type       ExternalType `json:"type" toml:"type" yaml:"type"`
	Encrypted  bool         `json:"encrypted" toml:"encrypted" yaml:"encrypted"`
	Exact      bool         `json:"exact" toml:"exact" yaml:"exact"`
	Executable bool         `json:"executable" toml:"executable" yaml:"executable"`
	Filter     struct {
		Command string   `json:"command" toml:"command" yaml:"command"`
		Args    []string `json:"args" toml:"args" yaml:"args"`
	} `json:"filter" toml:"filter" yaml:"filter"`
	Format          ArchiveFormat `json:"format" toml:"format" yaml:"format"`
	RefreshPeriod   time.Duration `json:"refreshPeriod" toml:"refreshPeriod" yaml:"refreshPeriod"`
	StripComponents int           `json:"stripComponents" toml:"stripComponents" yaml:"stripComponents"`
	URL             string        `json:"url" toml:"url" yaml:"url"`
}

// A externalCacheEntry is an external cache entry.
type externalCacheEntry struct {
	URL  string    `json:"url" toml:"url" time:"url"`
	Time time.Time `json:"time" toml:"time" yaml:"time"`
	Data []byte    `json:"data" toml:"data" yaml:"data"`
}

var externalCacheFormat = formatGzippedJSON{}

// A SourceState is a source state.
type SourceState struct {
	root                    sourceStateEntryTreeNode
	baseSystem              System
	system                  System
	sourceDirAbsPath        AbsPath
	destDirAbsPath          AbsPath
	cacheDirAbsPath         AbsPath
	umask                   fs.FileMode
	encryption              Encryption
	ignore                  *patternSet
	interpreters            map[string]*Interpreter
	httpClient              *http.Client
	logger                  *zerolog.Logger
	minVersion              semver.Version
	mode                    Mode
	defaultTemplateDataFunc func() map[string]interface{}
	readTemplateData        bool
	userTemplateData        map[string]interface{}
	priorityTemplateData    map[string]interface{}
	templateData            map[string]interface{}
	templateFuncs           template.FuncMap
	templateOptions         []string
	templates               map[string]*template.Template
	externals               map[RelPath]External
}

// A SourceStateOption sets an option on a source state.
type SourceStateOption func(*SourceState)

// WithBaseSystem sets the base system.
func WithBaseSystem(baseSystem System) SourceStateOption {
	return func(s *SourceState) {
		s.baseSystem = baseSystem
	}
}

// WithCacheDir sets the cache directory.
func WithCacheDir(cacheDirAbsPath AbsPath) SourceStateOption {
	return func(s *SourceState) {
		s.cacheDirAbsPath = cacheDirAbsPath
	}
}

// WithDestDir sets the destination directory.
func WithDestDir(destDirAbsPath AbsPath) SourceStateOption {
	return func(s *SourceState) {
		s.destDirAbsPath = destDirAbsPath
	}
}

// WithEncryption sets the encryption.
func WithEncryption(encryption Encryption) SourceStateOption {
	return func(s *SourceState) {
		s.encryption = encryption
	}
}

// WithHTTPClient sets the HTTP client.
func WithHTTPClient(httpClient *http.Client) SourceStateOption {
	return func(s *SourceState) {
		s.httpClient = httpClient
	}
}

// WithInterpreters sets the interpreters.
func WithInterpreters(interpreters map[string]*Interpreter) SourceStateOption {
	return func(s *SourceState) {
		s.interpreters = interpreters
	}
}

// WithLogger sets the logger.
func WithLogger(logger *zerolog.Logger) SourceStateOption {
	return func(s *SourceState) {
		s.logger = logger
	}
}

// WithMode sets the mode.
func WithMode(mode Mode) SourceStateOption {
	return func(s *SourceState) {
		s.mode = mode
	}
}

// WithPriorityTemplateData adds priority template data.
func WithPriorityTemplateData(priorityTemplateData map[string]interface{}) SourceStateOption {
	return func(s *SourceState) {
		RecursiveMerge(s.priorityTemplateData, priorityTemplateData)
	}
}

// WithReadTemplateData sets whether to read .chezmoidata.<format> files.
func WithReadTemplateData(readTemplateData bool) SourceStateOption {
	return func(s *SourceState) {
		s.readTemplateData = readTemplateData
	}
}

// WithSourceDir sets the source directory.
func WithSourceDir(sourceDirAbsPath AbsPath) SourceStateOption {
	return func(s *SourceState) {
		s.sourceDirAbsPath = sourceDirAbsPath
	}
}

// WithSystem sets the system.
func WithSystem(system System) SourceStateOption {
	return func(s *SourceState) {
		s.system = system
	}
}

// WithDefaultTemplateDataFunc sets the default template data function.
func WithDefaultTemplateDataFunc(defaultTemplateDataFunc func() map[string]interface{}) SourceStateOption {
	return func(s *SourceState) {
		s.defaultTemplateDataFunc = defaultTemplateDataFunc
	}
}

// WithTemplateFuncs sets the template functions.
func WithTemplateFuncs(templateFuncs template.FuncMap) SourceStateOption {
	return func(s *SourceState) {
		s.templateFuncs = templateFuncs
	}
}

// WithTemplateOptions sets the template options.
func WithTemplateOptions(templateOptions []string) SourceStateOption {
	return func(s *SourceState) {
		s.templateOptions = templateOptions
	}
}

// A targetStateEntryFunc returns a TargetStateEntry based on reading an AbsPath
// on a System.
type targetStateEntryFunc func(System, AbsPath) (TargetStateEntry, error)

// NewSourceState creates a new source state with the given options.
func NewSourceState(options ...SourceStateOption) *SourceState {
	s := &SourceState{
		umask:                Umask,
		encryption:           NoEncryption{},
		ignore:               newPatternSet(),
		httpClient:           http.DefaultClient,
		logger:               &log.Logger,
		readTemplateData:     true,
		priorityTemplateData: make(map[string]interface{}),
		userTemplateData:     make(map[string]interface{}),
		templateOptions:      DefaultTemplateOptions,
		externals:            make(map[RelPath]External),
	}
	for _, option := range options {
		option(s)
	}
	return s
}

// A PreAddFunc is called before a new source state entry is added.
type PreAddFunc func(targetRelPath RelPath, newSourceStateEntry, oldSourceStateEntry SourceStateEntry) error

// AddOptions are options to SourceState.Add.
type AddOptions struct {
	AutoTemplate     bool          // Automatically create templates, if possible.
	Create           bool          // Add create_ entries instead of normal entries.
	Empty            bool          // Add the empty_ attribute to added files.
	Encrypt          bool          // Encrypt files.
	EncryptedSuffix  string        // Suffix for encrypted files.
	Exact            bool          // Add the exact_ attribute to added directories.
	Include          *EntryTypeSet // Only add types in this set.
	PreAddFunc       PreAddFunc    // Function to be called before the source entry is added.
	RemoveDir        RelPath       // Directory to remove before adding.
	Template         bool          // Add the .tmpl attribute to added files.
	TemplateSymlinks bool          // Add symlinks with targets in the source or home directories as templates.
}

// Add adds destAbsPathInfos to s.
func (s *SourceState) Add(sourceSystem System, persistentState PersistentState, destSystem System, destAbsPathInfos map[AbsPath]fs.FileInfo, options *AddOptions) error {
	type sourceUpdate struct {
		destAbsPath    AbsPath
		entryState     *EntryState
		sourceRelPaths []SourceRelPath
	}

	destAbsPaths := make(AbsPaths, 0, len(destAbsPathInfos))
	for destAbsPath := range destAbsPathInfos {
		destAbsPaths = append(destAbsPaths, destAbsPath)
	}
	sort.Sort(destAbsPaths)

	sourceUpdates := make([]sourceUpdate, 0, len(destAbsPathInfos))
	newSourceStateEntries := make(map[SourceRelPath]SourceStateEntry)
	newSourceStateEntriesByTargetRelPath := make(map[RelPath]SourceStateEntry)
	nonEmptyDirs := make(map[SourceRelPath]struct{})
DESTABSPATH:
	for _, destAbsPath := range destAbsPaths {
		destAbsPathInfo := destAbsPathInfos[destAbsPath]
		if !options.Include.IncludeFileInfo(destAbsPathInfo) {
			continue
		}
		targetRelPath := destAbsPath.MustTrimDirPrefix(s.destDirAbsPath)

		if s.Ignore(targetRelPath) {
			continue
		}

		// Find the target's parent directory in the source state.
		var parentSourceRelPath SourceRelPath
		if targetParentRelPath := targetRelPath.Dir(); targetParentRelPath == DotRelPath {
			parentSourceRelPath = SourceRelPath{}
		} else if parentEntry, ok := newSourceStateEntriesByTargetRelPath[targetParentRelPath]; ok {
			parentSourceRelPath = parentEntry.SourceRelPath()
		} else if parentEntry := s.root.Get(targetParentRelPath); parentEntry != nil {
			parentSourceRelPath = parentEntry.SourceRelPath()
		} else {
			return fmt.Errorf("%s: parent directory not in source state", destAbsPath)
		}
		nonEmptyDirs[parentSourceRelPath] = struct{}{}

		actualStateEntry, err := NewActualStateEntry(destSystem, destAbsPath, destAbsPathInfo, nil)
		if err != nil {
			return err
		}
		newSourceStateEntry, err := s.sourceStateEntry(actualStateEntry, destAbsPath, destAbsPathInfo, parentSourceRelPath, options)
		if err != nil {
			return err
		}
		if newSourceStateEntry == nil {
			continue
		}

		sourceEntryRelPath := newSourceStateEntry.SourceRelPath()

		entryState, err := actualStateEntry.EntryState()
		if err != nil {
			return err
		}
		update := sourceUpdate{
			destAbsPath:    destAbsPath,
			entryState:     entryState,
			sourceRelPaths: []SourceRelPath{sourceEntryRelPath},
		}

		if oldSourceStateEntry := s.root.Get(targetRelPath); oldSourceStateEntry != nil {
			oldSourceEntryRelPath := oldSourceStateEntry.SourceRelPath()
			if !oldSourceEntryRelPath.Empty() && oldSourceEntryRelPath != sourceEntryRelPath {
				if options.PreAddFunc != nil {
					switch err := options.PreAddFunc(targetRelPath, newSourceStateEntry, oldSourceStateEntry); {
					case errors.Is(err, Skip):
						continue DESTABSPATH
					case err != nil:
						return err
					}
				}

				// If both the new and old source state entries are directories
				// but the name has changed, rename to avoid losing the
				// directory's contents. Otherwise, remove the old.
				_, newIsDir := newSourceStateEntry.(*SourceStateDir)
				_, oldIsDir := oldSourceStateEntry.(*SourceStateDir)
				if newIsDir && oldIsDir {
					newSourceStateEntry = &SourceStateRenameDir{
						oldSourceRelPath: oldSourceEntryRelPath,
						newSourceRelPath: sourceEntryRelPath,
					}
				} else {
					newSourceStateEntries[oldSourceEntryRelPath] = &SourceStateRemove{}
					update.sourceRelPaths = append(update.sourceRelPaths, oldSourceEntryRelPath)
				}
			}
		}

		newSourceStateEntries[sourceEntryRelPath] = newSourceStateEntry
		newSourceStateEntriesByTargetRelPath[targetRelPath] = newSourceStateEntry

		sourceUpdates = append(sourceUpdates, update)
	}

	// Create .keep files in empty added directories.
	for sourceEntryRelPath, sourceStateEntry := range newSourceStateEntries {
		if _, ok := sourceStateEntry.(*SourceStateDir); !ok {
			continue
		}
		if _, ok := nonEmptyDirs[sourceEntryRelPath]; ok {
			continue
		}

		dotKeepFileRelPath := sourceEntryRelPath.Join(NewSourceRelPath(".keep"))

		dotKeepFileSourceUpdate := sourceUpdate{
			entryState: &EntryState{
				Type: EntryStateTypeFile,
				Mode: 0o666 &^ s.umask,
			},
			sourceRelPaths: []SourceRelPath{dotKeepFileRelPath},
		}
		sourceUpdates = append(sourceUpdates, dotKeepFileSourceUpdate)

		newSourceStateEntries[dotKeepFileRelPath] = &SourceStateFile{
			targetStateEntry: &TargetStateFile{
				empty: true,
				perm:  0o666 &^ s.umask,
			},
		}
	}

	var sourceRoot sourceStateEntryTreeNode
	for sourceRelPath, sourceStateEntry := range newSourceStateEntries {
		sourceRoot.Set(sourceRelPath.RelPath(), sourceStateEntry)
	}

	// Simulate removing a directory by creating SourceStateRemove entries for
	// all existing source state entries that are in options.RemoveDir and not
	// in the new source state.
	if options.RemoveDir != EmptyRelPath {
		_ = s.root.ForEach(EmptyRelPath, func(targetRelPath RelPath, sourceStateEntry SourceStateEntry) error {
			if !targetRelPath.HasDirPrefix(options.RemoveDir) {
				return nil
			}
			if _, ok := newSourceStateEntriesByTargetRelPath[targetRelPath]; ok {
				return nil
			}
			sourceRelPath := sourceStateEntry.SourceRelPath()
			sourceRoot.Set(sourceRelPath.RelPath(), &SourceStateRemove{})
			update := sourceUpdate{
				destAbsPath: s.destDirAbsPath.Join(targetRelPath),
				entryState: &EntryState{
					Type: EntryStateTypeRemove,
				},
				sourceRelPaths: []SourceRelPath{sourceRelPath},
			}
			sourceUpdates = append(sourceUpdates, update)
			return nil
		})
	}

	targetSourceState := &SourceState{
		root: sourceRoot,
	}

	for _, sourceUpdate := range sourceUpdates {
		for _, sourceRelPath := range sourceUpdate.sourceRelPaths {
			if err := targetSourceState.Apply(sourceSystem, sourceSystem, NullPersistentState{}, s.sourceDirAbsPath, sourceRelPath.RelPath(), ApplyOptions{
				Include: options.Include,
				Umask:   s.umask,
			}); err != nil {
				return err
			}
		}
		if !sourceUpdate.destAbsPath.Empty() {
			if err := persistentStateSet(persistentState, EntryStateBucket, sourceUpdate.destAbsPath.Bytes(), sourceUpdate.entryState); err != nil {
				return err
			}
		}
	}

	return nil
}

// AddDestAbsPathInfos adds an fs.FileInfo to destAbsPathInfos for destAbsPath
// and any of its parents which are not already known.
func (s *SourceState) AddDestAbsPathInfos(destAbsPathInfos map[AbsPath]fs.FileInfo, system System, destAbsPath AbsPath, info fs.FileInfo) error {
	for {
		if _, err := destAbsPath.TrimDirPrefix(s.destDirAbsPath); err != nil {
			return err
		}

		if _, ok := destAbsPathInfos[destAbsPath]; ok {
			return nil
		}

		if info == nil {
			var err error
			info, err = system.Lstat(destAbsPath)
			if err != nil {
				return err
			}
		}
		destAbsPathInfos[destAbsPath] = info

		parentAbsPath := destAbsPath.Dir()
		if parentAbsPath == s.destDirAbsPath {
			return nil
		}
		parentRelPath := parentAbsPath.MustTrimDirPrefix(s.destDirAbsPath)
		if s.root.Get(parentRelPath) != nil {
			return nil
		}

		destAbsPath = parentAbsPath
		info = nil
	}
}

// A PreApplyFunc is called before a target is applied.
type PreApplyFunc func(targetRelPath RelPath, targetEntryState, lastWrittenEntryState, actualEntryState *EntryState) error

// ApplyOptions are options to SourceState.ApplyAll and SourceState.ApplyOne.
type ApplyOptions struct {
	Include      *EntryTypeSet
	PreApplyFunc PreApplyFunc
	Umask        fs.FileMode
}

// Apply updates targetRelPath in targetDir in destSystem to match s.
func (s *SourceState) Apply(targetSystem, destSystem System, persistentState PersistentState, targetDir AbsPath, targetRelPath RelPath, options ApplyOptions) error {
	sourceStateEntry := s.root.Get(targetRelPath)

	if !options.Include.IncludeEncrypted() {
		if sourceStateFile, ok := sourceStateEntry.(*SourceStateFile); ok && sourceStateFile.Attr.Encrypted {
			return nil
		}
	}

	destAbsPath := s.destDirAbsPath.Join(targetRelPath)
	targetStateEntry, err := sourceStateEntry.TargetStateEntry(destSystem, destAbsPath)
	if err != nil {
		return err
	}

	if options.Include != nil && !options.Include.IncludeTargetStateEntry(targetStateEntry) {
		return nil
	}

	targetAbsPath := targetDir.Join(targetRelPath)

	targetEntryState, err := targetStateEntry.EntryState(options.Umask)
	if err != nil {
		return err
	}

	switch skip, err := targetStateEntry.SkipApply(persistentState, targetAbsPath); {
	case err != nil:
		return err
	case skip:
		return nil
	}

	actualStateEntry, err := NewActualStateEntry(targetSystem, targetAbsPath, nil, nil)
	if err != nil {
		return err
	}

	if options.PreApplyFunc != nil {
		var lastWrittenEntryState *EntryState
		var entryState EntryState
		ok, err := persistentStateGet(persistentState, EntryStateBucket, targetAbsPath.Bytes(), &entryState)
		if err != nil {
			return err
		}
		if ok {
			lastWrittenEntryState = &entryState
		}

		actualEntryState, err := actualStateEntry.EntryState()
		if err != nil {
			return err
		}

		// Mitigate a bug in chezmoi before version 2.0.10 in a user-friendly
		// way.
		//
		// chezmoi before version 2.0.10 incorrectly stored the last written
		// entry state permissions, due to buggy umask handling. This caused
		// chezmoi apply to raise a false positive that a file or directory had
		// been modified since chezmoi last wrote it, since the permissions did
		// not match. Further compounding the problem, the diff presented to the
		// user was empty as the target state matched the actual state.
		//
		// The mitigation consists of several parts. First, detect that the bug
		// as precisely as possible by detecting where the the target state,
		// actual state, and last written entry state permissions match when the
		// umask is considered.
		//
		// If this is the case, then patch the last written entry state as if
		// the permissions were correctly stored.
		//
		// Finally, try to update the last written entry state in the persistent
		// state so we don't hit this path the next time the user runs chezmoi
		// apply. We ignore any errors because the persistent state might be in
		// read-only or dry-run mode.
		//
		// FIXME remove this mitigation in a later version of chezmoi
		switch {
		case lastWrittenEntryState == nil:
		case lastWrittenEntryState.Type == EntryStateTypeFile:
			if targetStateFile, ok := targetStateEntry.(*TargetStateFile); ok {
				if actualStateFile, ok := actualStateEntry.(*ActualStateFile); ok {
					if actualStateFile.perm.Perm() == targetStateFile.perm.Perm() {
						if targetStateFile.perm.Perm() != lastWrittenEntryState.Mode.Perm() {
							if targetStateFile.perm.Perm() == lastWrittenEntryState.Mode.Perm()&^s.umask {
								lastWrittenEntryState.Mode = targetStateFile.perm
								_ = persistentStateSet(persistentState, EntryStateBucket, targetAbsPath.Bytes(), lastWrittenEntryState)
							}
						}
					}
				}
			}
		case lastWrittenEntryState.Type == EntryStateTypeDir:
			if targetStateDir, ok := targetStateEntry.(*TargetStateDir); ok {
				if actualStateDir, ok := actualStateEntry.(*ActualStateDir); ok {
					if actualStateDir.perm.Perm() == targetStateDir.perm.Perm() {
						if targetStateDir.perm.Perm() != lastWrittenEntryState.Mode.Perm() {
							if targetStateDir.perm.Perm() == lastWrittenEntryState.Mode.Perm()&^s.umask {
								lastWrittenEntryState.Mode = fs.ModeDir | targetStateDir.perm
								_ = persistentStateSet(persistentState, EntryStateBucket, targetAbsPath.Bytes(), lastWrittenEntryState)
							}
						}
					}
				}
			}
		}

		// If the target entry state matches the actual entry state, but not the
		// last written entry state then silently update the last written entry
		// state. This handles the case where the user makes identical edits to
		// the source and target states: instead of reporting a diff with
		// respect to the last written state, we record the effect of the last
		// apply as the last written state.
		if targetEntryState.Equivalent(actualEntryState) && !lastWrittenEntryState.Equivalent(actualEntryState) {
			if err := persistentStateSet(persistentState, EntryStateBucket, targetAbsPath.Bytes(), targetEntryState); err != nil {
				return err
			}
			lastWrittenEntryState = targetEntryState
		}

		if err := options.PreApplyFunc(targetRelPath, targetEntryState, lastWrittenEntryState, actualEntryState); err != nil {
			return err
		}
	}

	if changed, err := targetStateEntry.Apply(targetSystem, persistentState, actualStateEntry); err != nil {
		return err
	} else if !changed {
		return nil
	}

	return persistentStateSet(persistentState, EntryStateBucket, targetAbsPath.Bytes(), targetEntryState)
}

// Contains returns the source state entry for targetRelPath.
func (s *SourceState) Contains(targetRelPath RelPath) bool {
	return s.root.Get(targetRelPath) != nil
}

// Encryption returns s's encryption.
func (s *SourceState) Encryption() Encryption {
	return s.encryption
}

// ExecuteTemplateData returns the result of executing template data.
func (s *SourceState) ExecuteTemplateData(name string, data []byte) ([]byte, error) {
	tmpl, err := template.New(name).
		Option(s.templateOptions...).
		Funcs(s.templateFuncs).
		Parse(string(data))
	if err != nil {
		return nil, err
	}

	for name, t := range s.templates {
		tmpl, err = tmpl.AddParseTree(name, t.Tree)
		if err != nil {
			return nil, err
		}
	}

	// Temporarily set .chezmoi.sourceFile to the name of the template.
	templateData := s.TemplateData()
	if chezmoiTemplateData, ok := templateData["chezmoi"].(map[string]interface{}); ok {
		chezmoiTemplateData["sourceFile"] = name
		defer delete(chezmoiTemplateData, "sourceFile")
	}

	builder := strings.Builder{}
	if err = tmpl.ExecuteTemplate(&builder, name, templateData); err != nil {
		return nil, err
	}
	return []byte(builder.String()), nil
}

// ForEach calls f for each source state entry.
func (s *SourceState) ForEach(f func(RelPath, SourceStateEntry) error) error {
	return s.root.ForEach(EmptyRelPath, func(targetRelPath RelPath, entry SourceStateEntry) error {
		return f(targetRelPath, entry)
	})
}

// Ignore returns if targetRelPath should be ignored.
func (s *SourceState) Ignore(targetRelPath RelPath) bool {
	return s.ignore.match(targetRelPath.String())
}

// MinVersion returns the minimum version for which s is valid.
func (s *SourceState) MinVersion() semver.Version {
	return s.minVersion
}

// MustEntry returns the source state entry associated with targetRelPath, and
// panics if it does not exist.
func (s *SourceState) MustEntry(targetRelPath RelPath) SourceStateEntry {
	sourceStateEntry := s.root.Get(targetRelPath)
	if sourceStateEntry == nil {
		panic(fmt.Sprintf("%s: not in source state", targetRelPath))
	}
	return sourceStateEntry
}

// ReadOptions are options to SourceState.Read.
type ReadOptions struct {
	RefreshExternals bool
	TimeNow          func() time.Time
}

// Read reads the source state from the source directory.
func (s *SourceState) Read(ctx context.Context, options *ReadOptions) error {
	switch info, err := s.system.Stat(s.sourceDirAbsPath); {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("%s: not a directory", s.sourceDirAbsPath)
	}

	// Read all source entries.
	allSourceStateEntries := make(map[RelPath][]SourceStateEntry)
	if err := WalkSourceDir(s.system, s.sourceDirAbsPath, func(sourceAbsPath AbsPath, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if sourceAbsPath == s.sourceDirAbsPath {
			return nil
		}
		sourceRelPath := SourceRelPath{
			relPath: sourceAbsPath.MustTrimDirPrefix(s.sourceDirAbsPath),
			isDir:   info.IsDir(),
		}

		parentSourceRelPath, sourceName := sourceRelPath.Split()
		// Follow symlinks in the source directory.
		if info.Mode().Type() == fs.ModeSymlink {
			// Some programs (notably emacs) use invalid symlinks as lockfiles.
			// To avoid following them and getting an ENOENT error, check first
			// if this is an entry that we will ignore anyway.
			if strings.HasPrefix(info.Name(), ignorePrefix) && !strings.HasPrefix(info.Name(), Prefix) {
				return nil
			}
			info, err = s.system.Stat(s.sourceDirAbsPath.Join(sourceRelPath.RelPath()))
			if err != nil {
				return err
			}
		}
		switch {
		case strings.HasPrefix(info.Name(), dataName):
			if !s.readTemplateData {
				return nil
			}
			return s.addTemplateData(sourceAbsPath)
		case strings.HasPrefix(info.Name(), externalName):
			return s.addExternal(sourceAbsPath)
		case info.Name() == ignoreName:
			return s.addPatterns(s.ignore, sourceAbsPath, parentSourceRelPath)
		case info.Name() == removeName:
			removePatterns := newPatternSet()
			if err := s.addPatterns(removePatterns, sourceAbsPath, sourceRelPath); err != nil {
				return err
			}
			matches, err := removePatterns.glob(s.system.UnderlyingFS(), s.destDirAbsPath.String()+"/")
			if err != nil {
				return err
			}
			n := 0
			for _, match := range matches {
				if !s.Ignore(NewRelPath(match)) {
					matches[n] = match
					n++
				}
			}
			targetParentRelPath := parentSourceRelPath.TargetRelPath(s.encryption.EncryptedSuffix())
			matches = matches[:n]
			for _, match := range matches {
				targetRelPath := targetParentRelPath.JoinString(match)
				sourceStateEntry := &SourceStateRemove{
					targetRelPath: targetRelPath,
				}
				allSourceStateEntries[targetRelPath] = append(allSourceStateEntries[targetRelPath], sourceStateEntry)
			}
			return nil
		case info.Name() == templatesDirName:
			if err := s.addTemplatesDir(sourceAbsPath); err != nil {
				return err
			}
			return vfs.SkipDir
		case info.Name() == versionName:
			return s.addVersionFile(sourceAbsPath)
		case strings.HasPrefix(info.Name(), Prefix):
			fallthrough
		case strings.HasPrefix(info.Name(), ignorePrefix):
			if info.IsDir() {
				return vfs.SkipDir
			}
			return nil
		case info.IsDir():
			da := parseDirAttr(sourceName.String())
			targetRelPath := parentSourceRelPath.Dir().TargetRelPath(s.encryption.EncryptedSuffix()).JoinString(da.TargetName)
			if s.Ignore(targetRelPath) {
				return vfs.SkipDir
			}
			sourceStateEntry := s.newSourceStateDir(sourceRelPath, da)
			allSourceStateEntries[targetRelPath] = append(allSourceStateEntries[targetRelPath], sourceStateEntry)
			return nil
		case info.Mode().IsRegular():
			fa := parseFileAttr(sourceName.String(), s.encryption.EncryptedSuffix())
			targetRelPath := parentSourceRelPath.Dir().TargetRelPath(s.encryption.EncryptedSuffix()).JoinString(fa.TargetName)
			if s.Ignore(targetRelPath) {
				return nil
			}
			var sourceStateEntry SourceStateEntry
			targetRelPath, sourceStateEntry = s.newSourceStateFile(sourceRelPath, fa, targetRelPath)
			allSourceStateEntries[targetRelPath] = append(allSourceStateEntries[targetRelPath], sourceStateEntry)
			return nil
		default:
			return &unsupportedFileTypeError{
				absPath: sourceAbsPath,
				mode:    info.Mode(),
			}
		}
	}); err != nil {
		return err
	}

	// Read externals.
	externalRelPaths := make(RelPaths, 0, len(s.externals))
	for externalRelPath := range s.externals {
		externalRelPaths = append(externalRelPaths, externalRelPath)
	}
	sort.Sort(externalRelPaths)
	for _, externalRelPath := range externalRelPaths {
		if s.Ignore(externalRelPath) {
			continue
		}
		external := s.externals[externalRelPath]
		parentRelPath, _ := externalRelPath.Split()
		var parentSourceRelPath SourceRelPath
		switch parentSourceStateEntry, err := s.root.MkdirAll(parentRelPath, external.URL, s.umask); {
		case err != nil:
			return err
		case parentSourceStateEntry != nil:
			parentSourceRelPath = parentSourceStateEntry.SourceRelPath()
		}
		externalSourceStateEntries, err := s.readExternal(ctx, externalRelPath, parentSourceRelPath, external, options)
		if err != nil {
			return err
		}
		for targetRelPath, sourceStateEntries := range externalSourceStateEntries {
			if s.Ignore(targetRelPath) {
				continue
			}
			allSourceStateEntries[targetRelPath] = append(allSourceStateEntries[targetRelPath], sourceStateEntries...)
		}
	}

	// Remove all ignored targets.
	for targetRelPath := range allSourceStateEntries {
		if s.Ignore(targetRelPath) {
			delete(allSourceStateEntries, targetRelPath)
		}
	}

	// Generate SourceStateRemoves for exact directories.
	for targetRelPath, sourceStateEntries := range allSourceStateEntries {
		if len(sourceStateEntries) != 1 {
			continue
		}

		switch sourceStateDir, ok := sourceStateEntries[0].(*SourceStateDir); {
		case !ok:
			continue
		case !sourceStateDir.Attr.Exact:
			continue
		}

		switch infos, err := s.system.ReadDir(s.destDirAbsPath.Join(targetRelPath)); {
		case err == nil:
			for _, info := range infos {
				name := info.Name()
				if name == "." || name == ".." {
					continue
				}
				destEntryRelPath := targetRelPath.JoinString(name)
				if _, ok := allSourceStateEntries[destEntryRelPath]; ok {
					continue
				}
				if s.Ignore(destEntryRelPath) {
					continue
				}
				allSourceStateEntries[destEntryRelPath] = append(allSourceStateEntries[destEntryRelPath], &SourceStateRemove{
					targetRelPath: destEntryRelPath,
				})
			}
		case errors.Is(err, fs.ErrNotExist):
			// Do nothing.
		default:
			return err
		}
	}

	// Check for inconsistent source entries. Iterate over the target names in
	// order so that any error is deterministic.
	targetRelPaths := make(RelPaths, 0, len(allSourceStateEntries))
	for targetRelPath := range allSourceStateEntries {
		targetRelPaths = append(targetRelPaths, targetRelPath)
	}
	sort.Sort(targetRelPaths)
	var err error
	for _, targetRelPath := range targetRelPaths {
		sourceStateEntries := allSourceStateEntries[targetRelPath]
		if len(sourceStateEntries) == 1 {
			continue
		}

		// Allow duplicate equivalent source entries for directories.
		if allEquivalentDirs(sourceStateEntries) {
			continue
		}

		origins := make([]string, 0, len(sourceStateEntries))
		for _, sourceStateEntry := range sourceStateEntries {
			origins = append(origins, sourceStateEntry.Origin())
		}
		sort.Strings(origins)
		err = multierr.Append(err, &inconsistentStateError{
			targetRelPath: targetRelPath,
			origins:       origins,
		})
	}
	if err != nil {
		return err
	}

	// Populate s.Entries with the unique source entry for each target.
	for targetRelPath, sourceEntries := range allSourceStateEntries {
		s.root.Set(targetRelPath, sourceEntries[0])
	}

	return nil
}

// TargetRelPaths returns all of s's target relative paths in order.
func (s *SourceState) TargetRelPaths() []RelPath {
	entries := s.root.Map()
	targetRelPaths := make([]RelPath, 0, len(entries))
	for targetRelPath := range entries {
		targetRelPaths = append(targetRelPaths, targetRelPath)
	}
	sort.Slice(targetRelPaths, func(i, j int) bool {
		orderI := entries[targetRelPaths[i]].Order()
		orderJ := entries[targetRelPaths[j]].Order()
		switch {
		case orderI < orderJ:
			return true
		case orderI == orderJ:
			return targetRelPaths[i].Less(targetRelPaths[j])
		default:
			return false
		}
	})
	return targetRelPaths
}

// TemplateData returns s's template data.
func (s *SourceState) TemplateData() map[string]interface{} {
	if s.templateData == nil {
		s.templateData = make(map[string]interface{})
		if s.defaultTemplateDataFunc != nil {
			RecursiveMerge(s.templateData, s.defaultTemplateDataFunc())
			s.defaultTemplateDataFunc = nil
		}
		RecursiveMerge(s.templateData, s.userTemplateData)
		RecursiveMerge(s.templateData, s.priorityTemplateData)
	}
	return s.templateData
}

// addExternal adds external source entries to s.
func (s *SourceState) addExternal(sourceAbsPath AbsPath) error {
	parentAbsPath, _ := sourceAbsPath.Split()

	parentRelPath, err := parentAbsPath.TrimDirPrefix(s.sourceDirAbsPath)
	if err != nil {
		return err
	}
	parentSourceRelPath := NewSourceRelDirPath(parentRelPath.String())
	parentTargetSourceRelPath := parentSourceRelPath.TargetRelPath(s.encryption.EncryptedSuffix())

	format, ok := Formats[strings.TrimPrefix(sourceAbsPath.Ext(), ".")]
	if !ok {
		return fmt.Errorf("%s: unknown format", sourceAbsPath)
	}
	data, err := s.executeTemplate(sourceAbsPath)
	if err != nil {
		return fmt.Errorf("%s: %w", sourceAbsPath, err)
	}
	externals := make(map[string]External)
	if err := format.Unmarshal(data, &externals); err != nil {
		return fmt.Errorf("%s: %w", sourceAbsPath, err)
	}
	for relPathStr, external := range externals {
		targetRelPath := parentTargetSourceRelPath.JoinString(relPathStr)
		if _, ok := s.externals[targetRelPath]; ok {
			return fmt.Errorf("%s: duplicate externals", targetRelPath)
		}
		s.externals[targetRelPath] = external
	}
	return nil
}

// addPatterns executes the template at sourceAbsPath, interprets the result as
// a list of patterns, and adds all patterns found to patternSet.
func (s *SourceState) addPatterns(patternSet *patternSet, sourceAbsPath AbsPath, sourceRelPath SourceRelPath) error {
	data, err := s.executeTemplate(sourceAbsPath)
	if err != nil {
		return err
	}
	dir := sourceRelPath.Dir().TargetRelPath("")
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		text := scanner.Text()
		if index := strings.IndexRune(text, '#'); index != -1 {
			text = text[:index]
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		include := true
		if strings.HasPrefix(text, "!") {
			include = false
			text = mustTrimPrefix(text, "!")
		}
		pattern := dir.JoinString(text).String()
		if err := patternSet.add(pattern, include); err != nil {
			return fmt.Errorf("%s:%d: %w", sourceAbsPath, lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("%s: %w", sourceAbsPath, err)
	}
	return nil
}

// addTemplateData adds all template data in sourceAbsPath to s.
func (s *SourceState) addTemplateData(sourceAbsPath AbsPath) error {
	format, ok := Formats[strings.TrimPrefix(sourceAbsPath.Ext(), ".")]
	if !ok {
		return fmt.Errorf("%s: unknown format", sourceAbsPath)
	}
	data, err := s.system.ReadFile(sourceAbsPath)
	if err != nil {
		return fmt.Errorf("%s: %w", sourceAbsPath, err)
	}
	var templateData map[string]interface{}
	if err := format.Unmarshal(data, &templateData); err != nil {
		return fmt.Errorf("%s: %w", sourceAbsPath, err)
	}
	RecursiveMerge(s.userTemplateData, templateData)
	return nil
}

// addTemplatesDir adds all templates in templateDir to s.
func (s *SourceState) addTemplatesDir(templatesDirAbsPath AbsPath) error {
	return WalkSourceDir(s.system, templatesDirAbsPath, func(templateAbsPath AbsPath, info fs.FileInfo, err error) error {
		switch {
		case err != nil:
			return err
		case info.Mode().IsRegular():
			contents, err := s.system.ReadFile(templateAbsPath)
			if err != nil {
				return err
			}
			templateRelPath := templateAbsPath.MustTrimDirPrefix(templatesDirAbsPath)
			name := templateRelPath.String()
			tmpl, err := template.New(name).Option(s.templateOptions...).Funcs(s.templateFuncs).Parse(string(contents))
			if err != nil {
				return err
			}
			if s.templates == nil {
				s.templates = make(map[string]*template.Template)
			}
			s.templates[name] = tmpl
			return nil
		case info.IsDir():
			return nil
		default:
			return &unsupportedFileTypeError{
				absPath: templateAbsPath,
				mode:    info.Mode(),
			}
		}
	})
}

// addVersionFile reads a .chezmoiversion file from source path and updates s's
// minimum version if it contains a more recent version than the current minimum
// version.
func (s *SourceState) addVersionFile(sourceAbsPath AbsPath) error {
	data, err := s.system.ReadFile(sourceAbsPath)
	if err != nil {
		return err
	}
	version, err := semver.NewVersion(strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}
	if s.minVersion.LessThan(*version) {
		s.minVersion = *version
	}
	return nil
}

// executeTemplate executes the template at path and returns the result.
func (s *SourceState) executeTemplate(templateAbsPath AbsPath) ([]byte, error) {
	data, err := s.system.ReadFile(templateAbsPath)
	if err != nil {
		return nil, err
	}
	return s.ExecuteTemplateData(templateAbsPath.String(), data)
}

// getExternalDataRaw returns the raw data for external at externalRelPath,
// possibly from the external cache.
func (s *SourceState) getExternalDataRaw(ctx context.Context, externalRelPath RelPath, external External, options *ReadOptions) ([]byte, error) {
	var now time.Time
	if options != nil && options.TimeNow != nil {
		now = options.TimeNow()
	} else {
		now = time.Now()
	}
	now = now.UTC()

	cacheKey := hex.EncodeToString(SHA256Sum([]byte(external.URL)))
	cachedDataAbsPath := s.cacheDirAbsPath.JoinString("external", cacheKey+"."+externalCacheFormat.Name())
	if options == nil || !options.RefreshExternals {
		if data, err := s.system.ReadFile(cachedDataAbsPath); err == nil {
			var externalCacheEntry externalCacheEntry
			if err := externalCacheFormat.Unmarshal(data, &externalCacheEntry); err == nil {
				if externalCacheEntry.URL == external.URL {
					if external.RefreshPeriod == 0 || externalCacheEntry.Time.Add(external.RefreshPeriod).After(now) {
						return externalCacheEntry.Data, nil
					}
				}
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, external.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient.Do(req)
	s.logger.Err(err).
		Str("method", req.Method).
		Int("statusCode", resp.StatusCode).
		Str("status", resp.Status).
		Stringer("url", req.URL).
		Msg("HTTP")
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || http.StatusMultipleChoices <= resp.StatusCode {
		return nil, fmt.Errorf("%s: %s: %s", externalRelPath, external.URL, resp.Status)
	}

	cachedExternalData, err := externalCacheFormat.Marshal(&externalCacheEntry{
		URL:  external.URL,
		Time: now,
		Data: data,
	})
	if err != nil {
		return nil, err
	}
	if err := MkdirAll(s.baseSystem, cachedDataAbsPath.Dir(), 0o700); err != nil {
		return nil, err
	}
	if err := s.baseSystem.WriteFile(cachedDataAbsPath, cachedExternalData, 0o600); err != nil {
		return nil, err
	}

	return data, nil
}

// getExternalDataRaw reads the external data for externalRelPath from
// external.URL.
func (s *SourceState) getExternalData(ctx context.Context, externalRelPath RelPath, external External, options *ReadOptions) ([]byte, error) {
	data, err := s.getExternalDataRaw(ctx, externalRelPath, external, options)
	if err != nil {
		return nil, err
	}

	if external.Encrypted {
		data, err = s.encryption.Decrypt(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", externalRelPath, external.URL, err)
		}
	}

	if external.Filter.Command != "" {
		//nolint:gosec
		cmd := exec.Command(external.Filter.Command, external.Filter.Args...)
		cmd.Stdin = bytes.NewReader(data)
		data, err = s.system.IdempotentCmdOutput(cmd)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", externalRelPath, external.URL, err)
		}
	}

	return data, nil
}

// newSourceStateDir returns a new SourceStateDir.
func (s *SourceState) newSourceStateDir(sourceRelPath SourceRelPath, dirAttr DirAttr) *SourceStateDir {
	targetStateDir := &TargetStateDir{
		perm: dirAttr.perm() &^ s.umask,
	}
	return &SourceStateDir{
		origin:           sourceRelPath.String(),
		sourceRelPath:    sourceRelPath,
		Attr:             dirAttr,
		targetStateEntry: targetStateDir,
	}
}

// newCreateTargetStateEntryFunc returns a targetStateEntryFunc that returns a
// file with sourceLazyContents if the file does not already exist, or returns
// the actual file's contents unchanged if the file already exists.
func (s *SourceState) newCreateTargetStateEntryFunc(sourceRelPath SourceRelPath, fileAttr FileAttr, sourceLazyContents *lazyContents) targetStateEntryFunc {
	return func(destSystem System, destAbsPath AbsPath) (TargetStateEntry, error) {
		var lazyContents *lazyContents
		switch contents, err := destSystem.ReadFile(destAbsPath); {
		case err == nil:
			lazyContents = newLazyContents(contents)
		case errors.Is(err, fs.ErrNotExist):
			lazyContents = newLazyContentsFunc(func() ([]byte, error) {
				contents, err = sourceLazyContents.Contents()
				if err != nil {
					return nil, err
				}
				if fileAttr.Template {
					contents, err = s.ExecuteTemplateData(sourceRelPath.String(), contents)
					if err != nil {
						return nil, err
					}
				}
				return contents, nil
			})
		default:
			return nil, err
		}
		return &TargetStateFile{
			lazyContents: lazyContents,
			empty:        true,
			perm:         fileAttr.perm() &^ s.umask,
		}, nil
	}
}

// newFileTargetStateEntryFunc returns a targetStateEntryFunc that returns a
// file with sourceLazyContents.
func (s *SourceState) newFileTargetStateEntryFunc(sourceRelPath SourceRelPath, fileAttr FileAttr, sourceLazyContents *lazyContents) targetStateEntryFunc {
	return func(destSystem System, destAbsPath AbsPath) (TargetStateEntry, error) {
		if s.mode == ModeSymlink && !fileAttr.Encrypted && !fileAttr.Executable && !fileAttr.Private && !fileAttr.Template {
			switch contents, err := sourceLazyContents.Contents(); {
			case err != nil:
				return nil, err
			case isEmpty(contents) && !fileAttr.Empty:
				return &TargetStateRemove{}, nil
			default:
				linkname := normalizeLinkname(s.sourceDirAbsPath.Join(sourceRelPath.RelPath()).String())
				return &TargetStateSymlink{
					lazyLinkname: newLazyLinkname(linkname),
				}, nil
			}
		}
		contentsFunc := func() ([]byte, error) {
			contents, err := sourceLazyContents.Contents()
			if err != nil {
				return nil, err
			}
			if fileAttr.Template {
				contents, err = s.ExecuteTemplateData(sourceRelPath.String(), contents)
				if err != nil {
					return nil, err
				}
			}
			return contents, nil
		}
		return &TargetStateFile{
			lazyContents: newLazyContentsFunc(contentsFunc),
			empty:        fileAttr.Empty,
			perm:         fileAttr.perm() &^ s.umask,
		}, nil
	}
}

// newModifyTargetStateEntryFunc returns a targetStateEntryFunc that returns a
// file with the contents modified by running the sourceLazyContents script.
func (s *SourceState) newModifyTargetStateEntryFunc(sourceRelPath SourceRelPath, fileAttr FileAttr, sourceLazyContents *lazyContents, interpreter *Interpreter) targetStateEntryFunc {
	return func(destSystem System, destAbsPath AbsPath) (TargetStateEntry, error) {
		contentsFunc := func() (contents []byte, err error) {
			// Read the current contents of the target.
			var currentContents []byte
			currentContents, err = destSystem.ReadFile(destAbsPath)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return
			}

			// Compute the contents of the modifier.
			var modifierContents []byte
			modifierContents, err = sourceLazyContents.Contents()
			if err != nil {
				return
			}
			if fileAttr.Template {
				modifierContents, err = s.ExecuteTemplateData(sourceRelPath.String(), modifierContents)
				if err != nil {
					return
				}
			}

			// If the modifier is empty then return the current contents unchanged.
			if isEmpty(modifierContents) {
				contents = currentContents
				return
			}

			// Write the modifier to a temporary file.
			var tempFile *os.File
			if tempFile, err = os.CreateTemp("", "*."+fileAttr.TargetName); err != nil {
				return
			}
			defer func() {
				err = multierr.Append(err, os.RemoveAll(tempFile.Name()))
			}()
			if runtime.GOOS != "windows" {
				if err = tempFile.Chmod(0o700); err != nil {
					return
				}
			}
			_, err = tempFile.Write(modifierContents)
			err = multierr.Append(err, tempFile.Close())
			if err != nil {
				return
			}

			// Run the modifier on the current contents.
			cmd := interpreter.ExecCommand(tempFile.Name())
			cmd.Stdin = bytes.NewReader(currentContents)
			cmd.Stderr = os.Stderr
			contents, err = destSystem.IdempotentCmdOutput(cmd)
			return
		}
		return &TargetStateFile{
			lazyContents: newLazyContentsFunc(contentsFunc),
			overwrite:    true,
			perm:         fileAttr.perm() &^ s.umask,
		}, nil
	}
}

// newRemoveTargetStateEntryFunc returns a targetStateEntryFunc that removes a
// target.
func (s *SourceState) newRemoveTargetStateEntryFunc(sourceRelPath SourceRelPath, fileAttr FileAttr) targetStateEntryFunc {
	return func(destSystem System, destAbsPath AbsPath) (TargetStateEntry, error) {
		return &TargetStateRemove{}, nil
	}
}

// newScriptTargetStateEntryFunc returns a targetStateEntryFunc that returns a
// script with sourceLazyContents.
func (s *SourceState) newScriptTargetStateEntryFunc(sourceRelPath SourceRelPath, fileAttr FileAttr, targetRelPath RelPath, sourceLazyContents *lazyContents, interpreter *Interpreter) targetStateEntryFunc {
	return func(destSystem System, destAbsPath AbsPath) (TargetStateEntry, error) {
		contentsFunc := func() ([]byte, error) {
			contents, err := sourceLazyContents.Contents()
			if err != nil {
				return nil, err
			}
			if fileAttr.Template {
				contents, err = s.ExecuteTemplateData(sourceRelPath.String(), contents)
				if err != nil {
					return nil, err
				}
			}
			return contents, nil
		}
		return &TargetStateScript{
			lazyContents: newLazyContentsFunc(contentsFunc),
			name:         targetRelPath,
			condition:    fileAttr.Condition,
			interpreter:  interpreter,
		}, nil
	}
}

// newSymlinkTargetStateEntryFunc returns a targetStateEntryFunc that returns a
// symlink with the linkname sourceLazyContents.
func (s *SourceState) newSymlinkTargetStateEntryFunc(sourceRelPath SourceRelPath, fileAttr FileAttr, sourceLazyContents *lazyContents) targetStateEntryFunc {
	return func(destSystem System, destAbsPath AbsPath) (TargetStateEntry, error) {
		linknameFunc := func() (string, error) {
			linknameBytes, err := sourceLazyContents.Contents()
			if err != nil {
				return "", err
			}
			if fileAttr.Template {
				linknameBytes, err = s.ExecuteTemplateData(sourceRelPath.String(), linknameBytes)
				if err != nil {
					return "", err
				}
			}
			linkname := normalizeLinkname(string(bytes.TrimSpace(linknameBytes)))
			return linkname, nil
		}
		return &TargetStateSymlink{
			lazyLinkname: newLazyLinknameFunc(linknameFunc),
		}, nil
	}
}

// newSourceStateFile returns a possibly new target RalPath and a new
// SourceStateFile.
func (s *SourceState) newSourceStateFile(sourceRelPath SourceRelPath, fileAttr FileAttr, targetRelPath RelPath) (RelPath, *SourceStateFile) {
	sourceLazyContents := newLazyContentsFunc(func() ([]byte, error) {
		contents, err := s.system.ReadFile(s.sourceDirAbsPath.Join(sourceRelPath.RelPath()))
		if err != nil {
			return nil, err
		}
		if fileAttr.Encrypted {
			contents, err = s.encryption.Decrypt(contents)
			if err != nil {
				return nil, err
			}
		}
		return contents, nil
	})

	var targetStateEntryFunc targetStateEntryFunc
	switch fileAttr.Type {
	case SourceFileTypeCreate:
		targetStateEntryFunc = s.newCreateTargetStateEntryFunc(sourceRelPath, fileAttr, sourceLazyContents)
	case SourceFileTypeFile:
		targetStateEntryFunc = s.newFileTargetStateEntryFunc(sourceRelPath, fileAttr, sourceLazyContents)
	case SourceFileTypeModify:
		// If the target has an extension, determine if it indicates an
		// interpreter to use.
		ext := strings.ToLower(strings.TrimPrefix(targetRelPath.Ext(), "."))
		interpreter := s.interpreters[ext]
		if interpreter != nil {
			// For modify scripts, the script extension is not considered part
			// of the target name, so remove it.
			targetRelPath = targetRelPath.Slice(0, targetRelPath.Len()-len(ext)-1)
		}
		targetStateEntryFunc = s.newModifyTargetStateEntryFunc(sourceRelPath, fileAttr, sourceLazyContents, interpreter)
	case SourceFileTypeRemove:
		targetStateEntryFunc = s.newRemoveTargetStateEntryFunc(sourceRelPath, fileAttr)
	case SourceFileTypeScript:
		// If the script has an extension, determine if it indicates an
		// interpreter to use.
		ext := strings.ToLower(strings.TrimPrefix(targetRelPath.Ext(), "."))
		interpreter := s.interpreters[ext]
		targetStateEntryFunc = s.newScriptTargetStateEntryFunc(sourceRelPath, fileAttr, targetRelPath, sourceLazyContents, interpreter)
	case SourceFileTypeSymlink:
		targetStateEntryFunc = s.newSymlinkTargetStateEntryFunc(sourceRelPath, fileAttr, sourceLazyContents)
	default:
		panic(fmt.Sprintf("%d: unsupported type", fileAttr.Type))
	}

	return targetRelPath, &SourceStateFile{
		lazyContents:         sourceLazyContents,
		origin:               sourceRelPath.String(),
		sourceRelPath:        sourceRelPath,
		Attr:                 fileAttr,
		targetStateEntryFunc: targetStateEntryFunc,
	}
}

// newSourceStateDirEntry returns a SourceStateEntry constructed from a
// directory in s.
//
// We return a SourceStateEntry rather than a *SourceStateDir to simplify nil
// checks later.
func (s *SourceState) newSourceStateDirEntry(info fs.FileInfo, parentSourceRelPath SourceRelPath, options *AddOptions) (SourceStateEntry, error) {
	dirAttr := DirAttr{
		TargetName: info.Name(),
		Exact:      options.Exact,
		Private:    isPrivate(info),
		ReadOnly:   isReadOnly(info),
	}
	sourceRelPath := parentSourceRelPath.Join(NewSourceRelDirPath(dirAttr.SourceName()))
	return &SourceStateDir{
		Attr:          dirAttr,
		origin:        sourceRelPath.String(),
		sourceRelPath: sourceRelPath,
		targetStateEntry: &TargetStateDir{
			perm: 0o777 &^ s.umask,
		},
	}, nil
}

// newSourceStateFileEntryFromFile returns a SourceStateEntry constructed from a
// file in s.
//
// We return a SourceStateEntry rather than a *SourceStateFile to simplify nil
// checks later.
func (s *SourceState) newSourceStateFileEntryFromFile(actualStateFile *ActualStateFile, info fs.FileInfo, parentSourceRelPath SourceRelPath, options *AddOptions) (SourceStateEntry, error) {
	fileAttr := FileAttr{
		TargetName: info.Name(),
		Empty:      options.Empty,
		Encrypted:  options.Encrypt,
		Executable: isExecutable(info),
		Private:    isPrivate(info),
		ReadOnly:   isReadOnly(info),
		Template:   options.Template,
	}
	if options.Create {
		fileAttr.Type = SourceFileTypeCreate
	} else {
		fileAttr.Type = SourceFileTypeFile
	}
	contents, err := actualStateFile.Contents()
	if err != nil {
		return nil, err
	}
	if options.AutoTemplate {
		var replacements bool
		contents, replacements = autoTemplate(contents, s.TemplateData())
		if replacements {
			fileAttr.Template = true
		}
	}
	if len(contents) == 0 && !options.Empty {
		return nil, nil
	}
	if options.Encrypt {
		contents, err = s.encryption.Encrypt(contents)
		if err != nil {
			return nil, err
		}
	}
	lazyContents := newLazyContents(contents)
	sourceRelPath := parentSourceRelPath.Join(NewSourceRelPath(fileAttr.SourceName(s.encryption.EncryptedSuffix())))
	return &SourceStateFile{
		Attr:          fileAttr,
		origin:        sourceRelPath.String(),
		sourceRelPath: sourceRelPath,
		lazyContents:  lazyContents,
		targetStateEntry: &TargetStateFile{
			lazyContents: lazyContents,
			empty:        options.Empty,
			perm:         0o666 &^ s.umask,
		},
	}, nil
}

// newSourceStateFileEntryFromSymlink returns a SourceStateEntry constructed
// from a symlink in s.
//
// We return a SourceStateEntry rather than a *SourceStateFile to simplify nil
// checks later.
func (s *SourceState) newSourceStateFileEntryFromSymlink(actualStateSymlink *ActualStateSymlink, info fs.FileInfo, parentSourceRelPath SourceRelPath, options *AddOptions) (SourceStateEntry, error) {
	linkname, err := actualStateSymlink.Linkname()
	if err != nil {
		return nil, err
	}
	contents := []byte(linkname)
	template := false
	switch {
	case options.AutoTemplate:
		contents, template = autoTemplate(contents, s.TemplateData())
	case options.Template:
		template = true
	case !options.Template && options.TemplateSymlinks:
		switch {
		case strings.HasPrefix(linkname, s.sourceDirAbsPath.String()+"/"):
			contents = []byte("{{ .chezmoi.sourceDir }}/" + linkname[s.sourceDirAbsPath.Len()+1:])
			template = true
		case strings.HasPrefix(linkname, s.destDirAbsPath.String()+"/"):
			contents = []byte("{{ .chezmoi.homeDir }}/" + linkname[s.destDirAbsPath.Len()+1:])
			template = true
		}
	}
	contents = append(contents, '\n')
	lazyContents := newLazyContents(contents)
	fileAttr := FileAttr{
		TargetName: info.Name(),
		Type:       SourceFileTypeSymlink,
		Template:   template,
	}
	sourceRelPath := parentSourceRelPath.Join(NewSourceRelPath(fileAttr.SourceName(s.encryption.EncryptedSuffix())))
	return &SourceStateFile{
		Attr:          fileAttr,
		sourceRelPath: sourceRelPath,
		lazyContents:  lazyContents,
		targetStateEntry: &TargetStateFile{
			lazyContents: lazyContents,
			perm:         0o666 &^ s.umask,
		},
	}, nil
}

// readExternal reads an external and returns its SourceStateEntries.
func (s *SourceState) readExternal(ctx context.Context, externalRelPath RelPath, parentSourceRelPath SourceRelPath, external External, options *ReadOptions) (map[RelPath][]SourceStateEntry, error) {
	switch external.Type {
	case ExternalTypeArchive:
		return s.readExternalArchive(ctx, externalRelPath, parentSourceRelPath, external, options)
	case ExternalTypeFile:
		return s.readExternalFile(ctx, externalRelPath, parentSourceRelPath, external, options)
	default:
		return nil, fmt.Errorf("%s: unknown external type: %s", externalRelPath, external.Type)
	}
}

// readExternalArchive reads an external archive and returns its
// SourceStateEntries.
func (s *SourceState) readExternalArchive(ctx context.Context, externalRelPath RelPath, parentSourceRelPath SourceRelPath, external External, options *ReadOptions) (map[RelPath][]SourceStateEntry, error) {
	data, err := s.getExternalData(ctx, externalRelPath, external, options)
	if err != nil {
		return nil, err
	}

	url, err := url.Parse(external.URL)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", externalRelPath, external.URL, err)
	}
	urlPath := url.Path
	if external.Encrypted {
		urlPath = strings.TrimSuffix(urlPath, s.encryption.EncryptedSuffix())
	}
	dirAttr := DirAttr{
		TargetName: externalRelPath.Base(),
		Exact:      external.Exact,
	}
	sourceStateDir := &SourceStateDir{
		Attr:          dirAttr,
		origin:        external.URL,
		sourceRelPath: parentSourceRelPath.Join(NewSourceRelPath(dirAttr.SourceName())),
		targetStateEntry: &TargetStateDir{
			perm: 0o777 &^ s.umask,
		},
	}
	sourceStateEntries := map[RelPath][]SourceStateEntry{
		externalRelPath: {sourceStateDir},
	}

	format := external.Format
	if format == ArchiveFormatUnknown {
		format = GuessArchiveFormat(urlPath, data)
	}

	sourceRelPaths := make(map[RelPath]SourceRelPath)
	if err := walkArchive(data, format, func(name string, info fs.FileInfo, r io.Reader, linkname string) error {
		if external.StripComponents > 0 {
			components := strings.Split(name, "/")
			if len(components) <= external.StripComponents {
				return nil
			}
			name = path.Join(components[external.StripComponents:]...)
		}
		if name == "" {
			return nil
		}
		targetRelPath := externalRelPath.JoinString(name)

		if s.Ignore(targetRelPath) {
			return nil
		}

		dirTargetRelPath, _ := targetRelPath.Split()
		dirSourceRelPath := sourceRelPaths[dirTargetRelPath]

		var sourceStateEntry SourceStateEntry
		switch {
		case info.IsDir():
			targetStateEntry := &TargetStateDir{
				perm: info.Mode().Perm() &^ s.umask,
			}
			dirAttr := DirAttr{
				TargetName: info.Name(),
				Exact:      external.Exact,
				Private:    isPrivate(info),
				ReadOnly:   isReadOnly(info),
			}
			sourceStateEntry = &SourceStateDir{
				Attr:             dirAttr,
				origin:           external.URL,
				sourceRelPath:    parentSourceRelPath.Join(dirSourceRelPath, NewSourceRelPath(dirAttr.SourceName())),
				targetStateEntry: targetStateEntry,
			}
		case info.Mode()&fs.ModeType == 0:
			contents, err := io.ReadAll(r)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			lazyContents := newLazyContents(contents)
			fileAttr := FileAttr{
				TargetName: info.Name(),
				Type:       SourceFileTypeFile,
				Empty:      info.Size() == 0,
				Executable: isExecutable(info),
				Private:    isPrivate(info),
				ReadOnly:   isReadOnly(info),
			}
			targetStateEntry := &TargetStateFile{
				lazyContents: lazyContents,
				empty:        fileAttr.Empty,
				perm:         fileAttr.perm() &^ s.umask,
			}
			sourceStateEntry = &SourceStateFile{
				lazyContents:     lazyContents,
				Attr:             fileAttr,
				origin:           external.URL,
				sourceRelPath:    parentSourceRelPath.Join(dirSourceRelPath, NewSourceRelPath(fileAttr.SourceName(s.encryption.EncryptedSuffix()))),
				targetStateEntry: targetStateEntry,
			}
		case info.Mode()&fs.ModeType == fs.ModeSymlink:
			targetStateEntry := &TargetStateSymlink{
				lazyLinkname: newLazyLinkname(linkname),
			}
			fileAttr := FileAttr{
				TargetName: info.Name(),
				Type:       SourceFileTypeSymlink,
			}
			sourceStateEntry = &SourceStateFile{
				Attr:             fileAttr,
				origin:           external.URL,
				sourceRelPath:    parentSourceRelPath.Join(dirSourceRelPath, NewSourceRelPath(fileAttr.SourceName(s.encryption.EncryptedSuffix()))),
				targetStateEntry: targetStateEntry,
			}
		default:
			return fmt.Errorf("%s: unsupported mode %o", name, info.Mode()&fs.ModeType)
		}
		sourceStateEntries[targetRelPath] = append(sourceStateEntries[targetRelPath], sourceStateEntry)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("%s: %s: %w", externalRelPath, external.URL, err)
	}

	return sourceStateEntries, nil
}

// readExternalFile reads an external file and returns its SourceStateEntries.
func (s *SourceState) readExternalFile(ctx context.Context, externalRelPath RelPath, parentSourceRelPath SourceRelPath, external External, options *ReadOptions) (map[RelPath][]SourceStateEntry, error) {
	lazyContents := newLazyContentsFunc(func() ([]byte, error) {
		return s.getExternalData(ctx, externalRelPath, external, options)
	})
	fileAttr := FileAttr{
		Empty:      true,
		Executable: external.Executable,
	}
	targetStateEntry := &TargetStateFile{
		lazyContents: lazyContents,
		empty:        fileAttr.Empty,
		perm:         fileAttr.perm() &^ s.umask,
	}
	sourceStateEntry := &SourceStateFile{
		origin:           external.URL,
		sourceRelPath:    parentSourceRelPath.Join(NewSourceRelPath(fileAttr.SourceName(s.encryption.EncryptedSuffix()))),
		targetStateEntry: targetStateEntry,
	}
	return map[RelPath][]SourceStateEntry{
		externalRelPath: {sourceStateEntry},
	}, nil
}

// sourceStateEntry returns a new SourceStateEntry based on actualStateEntry.
func (s *SourceState) sourceStateEntry(actualStateEntry ActualStateEntry, destAbsPath AbsPath, info fs.FileInfo, parentSourceRelPath SourceRelPath, options *AddOptions) (SourceStateEntry, error) {
	switch actualStateEntry := actualStateEntry.(type) {
	case *ActualStateAbsent:
		return nil, fmt.Errorf("%s: not found", destAbsPath)
	case *ActualStateDir:
		return s.newSourceStateDirEntry(info, parentSourceRelPath, options)
	case *ActualStateFile:
		return s.newSourceStateFileEntryFromFile(actualStateEntry, info, parentSourceRelPath, options)
	case *ActualStateSymlink:
		return s.newSourceStateFileEntryFromSymlink(actualStateEntry, info, parentSourceRelPath, options)
	default:
		panic(fmt.Sprintf("%T: unsupported type", actualStateEntry))
	}
}

// allEquivalentDirs returns if sourceStateEntries are all equivalent
// directories.
func allEquivalentDirs(sourceStateEntries []SourceStateEntry) bool {
	sourceStateDir0, ok := sourceStateEntries[0].(*SourceStateDir)
	if !ok {
		return false
	}
	for _, sourceStateEntry := range sourceStateEntries[1:] {
		sourceStateDir, ok := sourceStateEntry.(*SourceStateDir)
		if !ok {
			return false
		}
		if sourceStateDir0.Attr != sourceStateDir.Attr {
			return false
		}
	}
	return true
}
