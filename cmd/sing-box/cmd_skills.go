package main

import (
	"embed"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

//go:embed skills
var skillsFS embed.FS

var (
	skillNames    []string
	skillNamesMap map[string]bool
)

func init() {
	entries := common.Must1(skillsFS.ReadDir("skills"))
	skillNames = make([]string, 0, len(entries))
	skillNamesMap = make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		skillNames = append(skillNames, name)
		skillNamesMap[name] = true
	}
	commandSkillInstall.ValidArgs = append([]string{"all"}, skillNames...)
}

var commandSkillFlagInstallDir string

var commandSkill = &cobra.Command{
	Use:     "skill",
	Aliases: []string{"skills"},
	Short:   "Manage sing-box skills",
}

var commandSkillList = &cobra.Command{
	Use:   "list",
	Short: "List available skills",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		for _, name := range skillNames {
			os.Stdout.WriteString(name + "\n")
		}
	},
}

var commandSkillInstall = &cobra.Command{
	Use:   "install <name>...",
	Short: "Install skills",
	Long:  "Install skills bundled in sing-box.\n\nUse \"all\" to install every available skill.",
	Args:  cobra.MatchAll(cobra.MinimumNArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		err := runSkillInstall(args)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandSkillInstall.Flags().StringVar(&commandSkillFlagInstallDir, "install-dir", "", "skill install directory (default: ~/.agents/skills)")
	commandSkill.AddCommand(commandSkillList)
	commandSkill.AddCommand(commandSkillInstall)
	mainCommand.AddCommand(commandSkill)
}

func runSkillInstall(names []string) error {
	installDir := commandSkillFlagInstallDir
	if installDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return E.Cause(err, "determine home directory")
		}
		installDir = filepath.Join(home, ".agents", "skills")
	}
	var targets []string
	if common.Contains(names, "all") {
		targets = slices.Clone(skillNames)
	} else {
		seen := make(map[string]bool, len(names))
		targets = make([]string, 0, len(names))
		for _, name := range names {
			if !skillNamesMap[name] {
				return E.New("unknown skill: ", name)
			}
			if seen[name] {
				continue
			}
			targets = append(targets, name)
			seen[name] = true
		}
	}
	for _, name := range targets {
		err := installSkill(installDir, name)
		if err != nil {
			return E.Cause(err, "install skill ", name)
		}
	}
	return nil
}

func installSkill(installDir string, name string) error {
	sourceDir := path.Join("skills", name)
	return fs.WalkDir(skillsFS, sourceDir, func(sourcePath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relativePath := strings.TrimPrefix(sourcePath, sourceDir)
		destinationPath := filepath.Join(installDir, name, filepath.FromSlash(relativePath))
		if entry.IsDir() {
			return os.MkdirAll(destinationPath, 0o755)
		}
		sourceFile, err := skillsFS.Open(sourcePath)
		if err != nil {
			return err
		}
		defer sourceFile.Close()
		err = os.MkdirAll(filepath.Dir(destinationPath), 0o755)
		if err != nil {
			return err
		}
		// embed.FS reports every file as 0o444, so the executable bit has to be
		// restored by convention: everything under scripts/ is a script.
		mode := os.FileMode(0o644)
		if strings.HasPrefix(relativePath, "/scripts/") {
			mode = 0o755
		}
		destinationFile, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		defer destinationFile.Close()
		_, err = bufio.Copy(destinationFile, sourceFile)
		if err != nil {
			return err
		}
		err = os.Chmod(destinationPath, mode)
		if err != nil {
			log.Warn(E.Cause(err, "chmod ", destinationPath, " to ", mode))
		}
		log.Info("installed ", destinationPath)
		return nil
	})
}
