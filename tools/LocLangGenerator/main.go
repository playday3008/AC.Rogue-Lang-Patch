package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"slices"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	cross_dialog "github.com/sqweek/dialog"
)

var langList = []string{
	"None",
	"English",
	"French",
	"Spanish",
	"Polish",
	"German",
	"ChineseTrad",
	"Hungarian",
	"Italian",
	"Japanese",
	"Czech",
	"Korean",
	"Russian",
	"Dutch",
	"Danish",
	"Norwegian",
	"Swedish",
	"Portuguese",
	"Brazil",
	"Finnish",
	"Arabic",
	"Mexican",
	"LocTest",
}

func main() {
	myApp := app.New()
	windows := myApp.NewWindow("AC: Rogue Language Config Generator")

	subtitleDropList := widget.NewSelect(nil, nil)
	audioDropList := widget.NewSelect(nil, nil)

	subtitleCheckList := widget.NewCheckGroup(langList, func(selected []string) {
		subtitleDropList.Options = []string{}
		for _, lang := range langList {
			if slices.Contains(selected, lang) {
				subtitleDropList.Options = append(subtitleDropList.Options, lang)
			}
		}
		subtitleDropList.Refresh()
	})
	audioCheckList := widget.NewCheckGroup(langList, func(selected []string) {
		audioDropList.Options = []string{}
		for _, lang := range langList {
			if slices.Contains(selected, lang) {
				audioDropList.Options = append(audioDropList.Options, lang)
			}
		}
		audioDropList.Refresh()
	})

	resetButton := widget.NewButton("Reset", func() {
		subtitleCheckList.Selected = []string{}
		subtitleDropList.Options = []string{}
		subtitleDropList.Selected = "(Select one)"
		subtitleCheckList.Refresh()
		subtitleDropList.Refresh()

		audioCheckList.Selected = []string{}
		audioDropList.Options = []string{}
		audioDropList.Selected = "(Select one)"
		audioCheckList.Refresh()
		audioDropList.Refresh()
	})

	loadButton := widget.NewButton("Load", func() {
		filename, err := cross_dialog.File().Title("Load").Filter("Language Config Files", "lang").Filter("All files", "*").Load()
		if err != nil {
			if err != cross_dialog.ErrCancelled {
				dialog.ShowError(err, windows)
			}
			return
		}
		file, err := os.OpenFile(filename, os.O_RDONLY, 0644)
		if err != nil {
			dialog.ShowError(err, windows)
			return
		}
		if file == nil {
			return
		}
		defer file.Close()

		var header [4]byte
		var subtitleIdx, audioIdx [1]byte
		subtitleBitfield := make([]byte, 4)
		audioBitfield := make([]byte, 4)

		{
			fmt.Printf("Reading file:\n")

			n, err := file.Read(header[:])
			if err != nil {
				dialog.ShowError(err, windows)
				return
			} else if n != 4 || string(header[:]) != "LANG" {
				dialog.ShowError(fmt.Errorf("%s", "Invalid file format"), windows)
				return
			}
			fmt.Printf("\tHeader:\t\t%s\n", header[:])

			n, err = file.Read(subtitleIdx[:])
			if err != nil {
				dialog.ShowError(err, windows)
				return
			} else if n != 1 || subtitleIdx[0] > 0x1f {
				dialog.ShowError(fmt.Errorf("%s", "Invalid file format"), windows)
				return
			}
			fmt.Printf("\tSubtitleIdx:\t%d\n", subtitleIdx[0])

			n, err = file.Read(subtitleBitfield)
			if err != nil {
				dialog.ShowError(err, windows)
				return
			} else if n != 4 {
				dialog.ShowError(fmt.Errorf("%s", "Invalid file format"), windows)
				return
			}
			fmt.Printf("\tSubtitleBytes:\t%v\n", subtitleBitfield)

			n, err = file.Read(audioBitfield)
			if err != nil {
				dialog.ShowError(err, windows)
				return
			} else if n != 4 {
				dialog.ShowError(fmt.Errorf("%s", "Invalid file format"), windows)
				return
			}
			fmt.Printf("\tAudioBytes:\t%v\n", audioBitfield)

			n, err = file.Read(audioIdx[:])
			if err != nil {
				dialog.ShowError(err, windows)
				return
			} else if n != 1 || audioIdx[0] > 0x1f {
				dialog.ShowError(fmt.Errorf("%s", "Invalid file format"), windows)
				return
			}
			fmt.Printf("\tAudioIdx:\t%d\n", audioIdx[0])
		}

		subtitleBits := binary.BigEndian.Uint32(subtitleBitfield)
		audioBits := binary.BigEndian.Uint32(audioBitfield)

		subtitleCheckList.Selected = []string{}
		audioCheckList.Selected = []string{}
		for i := 0; i < len(langList); i++ {
			if subtitleBits&(1<<uint(i)) != 0 {
				subtitleCheckList.Selected = append(subtitleCheckList.Selected, langList[i])
			}
			if audioBits&(1<<uint(i)) != 0 {
				audioCheckList.Selected = append(audioCheckList.Selected, langList[i])
			}
		}

		subtitleDropList.Options = subtitleCheckList.Selected
		subtitleDropList.Selected = langList[subtitleIdx[0]]
		subtitleDropList.Refresh()

		audioDropList.Options = audioCheckList.Selected
		audioDropList.Selected = langList[audioIdx[0]]
		audioDropList.Refresh()

		subtitleCheckList.Refresh()
		audioCheckList.Refresh()
	})

	saveButton := widget.NewButton("Save", func() {
		filename, err := cross_dialog.File().Title("Load").Filter("Language Config Files", "lang").Filter("All files", "*").Save()
		if err != nil {
			if err != cross_dialog.ErrCancelled {
				dialog.ShowError(err, windows)
			}
			return
		}
		file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			dialog.ShowError(err, windows)
			return
		}
		if file == nil {
			return
		}
		defer file.Close()

		subtitleIdx := byte(0xFF)
		subtitleBits := uint32(0)
		audioBits := uint32(0)
		audioIdx := byte(0xFF)

		for i, lang := range langList {
			if slices.Contains(subtitleCheckList.Selected, lang) {
				subtitleBits |= 1 << uint(i)
			}
			if slices.Contains(audioCheckList.Selected, lang) {
				audioBits |= 1 << uint(i)
			}
		}

		for i, lang := range langList {
			if lang == subtitleDropList.Selected {
				subtitleIdx = byte(i)
			}
			if lang == audioDropList.Selected {
				audioIdx = byte(i)
			}
		}
		if subtitleIdx == 0xFF || audioIdx == 0xFF {
			dialog.ShowError(fmt.Errorf("%s", "Invalid preferred language selection"), windows)
			return
		}

		subtitleBitfield := make([]byte, 4)
		audioBitfield := make([]byte, 4)

		binary.BigEndian.PutUint32(subtitleBitfield, subtitleBits)
		binary.BigEndian.PutUint32(audioBitfield, audioBits)

		{
			fmt.Printf("Writing file:\n")

			_, err := file.Write([]byte("LANG"))
			if err != nil {
				dialog.ShowError(err, windows)
				return
			}
			fmt.Printf("\tHeader:\t\tLANG\n")

			_, err = file.Write([]byte{subtitleIdx})
			if err != nil {
				dialog.ShowError(err, windows)
				return
			}
			fmt.Printf("\tSubtitleIdx:\t%d\n", subtitleIdx)

			_, err = file.Write(subtitleBitfield)
			if err != nil {
				dialog.ShowError(err, windows)
				return
			}
			fmt.Printf("\tSubtitleBytes:\t%v\n", subtitleBitfield)

			_, err = file.Write(audioBitfield)
			if err != nil {
				dialog.ShowError(err, windows)
				return
			}
			fmt.Printf("\tAudioBytes:\t%v\n", audioBitfield)

			_, err = file.Write([]byte{audioIdx})
			if err != nil {
				dialog.ShowError(err, windows)
				return
			}
			fmt.Printf("\tAudioIdx:\t%d\n", audioIdx)
		}
	})

	windows.SetContent(
		container.NewBorder(
			nil,
			container.NewVBox(
				widget.NewSeparator(),
				container.NewHBox(
					layout.NewSpacer(),
					resetButton,
					loadButton,
					saveButton,
				),
			),
			nil, nil,
			container.NewHBox(
				container.NewBorder(
					container.NewVBox(
						container.NewHBox(
							layout.NewSpacer(),
							widget.NewLabel("Subtitle Languages"),
							layout.NewSpacer(),
						),
						widget.NewSeparator(),
					),
					nil, nil, nil,
					container.NewStack(
						container.NewHBox(
							container.NewBorder(
								container.NewVBox(
									container.NewHBox(
										layout.NewSpacer(),
										widget.NewLabel("Available"),
										layout.NewSpacer(),
									),
									widget.NewSeparator(),
								),
								nil, nil, nil,
								container.NewVScroll(
									subtitleCheckList,
								),
							),
							widget.NewSeparator(),
							container.NewBorder(
								container.NewVBox(
									container.NewHBox(
										layout.NewSpacer(),
										widget.NewLabel("Preferred"),
										layout.NewSpacer(),
									),
									widget.NewSeparator(),
								),
								nil, nil, nil,
								container.NewVBox(
									subtitleDropList,
								),
							),
						),
					),
				),
				widget.NewSeparator(),
				container.NewBorder(
					container.NewVBox(
						container.NewHBox(
							layout.NewSpacer(),
							widget.NewLabel("Audio Languages"),
							layout.NewSpacer(),
						),
						widget.NewSeparator(),
					),
					nil, nil, nil,
					container.NewStack(
						container.NewHBox(
							container.NewBorder(
								container.NewVBox(
									container.NewHBox(
										layout.NewSpacer(),
										widget.NewLabel("Available"),
										layout.NewSpacer(),
									),
									widget.NewSeparator(),
								),
								nil, nil, nil,
								container.NewVScroll(
									audioCheckList,
								),
							),
							widget.NewSeparator(),
							container.NewBorder(
								container.NewVBox(
									container.NewHBox(
										layout.NewSpacer(),
										widget.NewLabel("Preferred"),
										layout.NewSpacer(),
									),
									widget.NewSeparator(),
								),
								nil, nil, nil,
								container.NewVBox(
									audioDropList,
								),
							),
						),
					),
				),
			),
		),
	)

	myApp.Settings().SetTheme(theme.DefaultTheme())
	windows.Resize(fyne.NewSize(windows.Canvas().Size().Width, 600))
	windows.SetFixedSize(true)
	windows.ShowAndRun()
}
