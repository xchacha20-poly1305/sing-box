package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/sagernet/sing-box/common/speedtest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/byteformats"
	N "github.com/sagernet/sing/common/network"

	"github.com/spf13/cobra"
)

var (
	commandSpeedTestSkipUpload   bool
	commandSpeedTestSkipDownload bool
	commandSpeedTestUseBytes     bool
	commandSpeedTestDataSize     uint32
	commandSpeedTestTimeout      time.Duration
)

var commandSpeedTest = &cobra.Command{
	Use:   "speedtest",
	Short: "Test server speed",
	Run: func(cmd *cobra.Command, args []string) {
		err := doSpeedtest()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandSpeedTest.Flags().BoolVar(&commandSpeedTestSkipUpload, "skip-upload", false, "skip upload test")
	commandSpeedTest.Flags().BoolVar(&commandSpeedTestSkipDownload, "skip-download", false, "skip download test")
	commandSpeedTest.Flags().BoolVar(&commandSpeedTestUseBytes, "use-bytes", false, "Use bytes per second instead of bits per second")
	commandSpeedTest.Flags().Uint32Var(&commandSpeedTestDataSize, "data-size", 1024*1024*100, "Data size for download and upload tests")
	commandSpeedTest.Flags().DurationVar(&commandSpeedTestTimeout, "timeout", time.Minute, "limit duration")
	commandTools.AddCommand(commandSpeedTest)
}

func doSpeedtest() error {
	instance, err := createPreStartedClient()
	if err != nil {
		return err
	}
	defer instance.Close()
	dialer, err := createDialer(instance, commandToolsFlagOutbound)
	if err != nil {
		return err
	}
	globalCtx, cancel := signal.NotifyContext(globalCtx, os.Interrupt)
	defer cancel()
	done := make(chan struct{})
	go func() {
		if !commandSpeedTestSkipDownload {
			log.Info("starting download test...")
			err := downloadTest(globalCtx, dialer)
			if err != nil {
				log.Error("download test failed: ", err)
			}
		}
		if !commandSpeedTestSkipUpload {
			log.Info("starting upload test...")
			err := uploadTest(globalCtx, dialer)
			if err != nil {
				log.Error("upload test failed: ", err)
			}
		}

		close(done)
	}()

	select {
	case <-globalCtx.Done():
		return globalCtx.Err()
	case <-done:
		return nil
	}
}

func downloadTest(ctx context.Context, dialer N.Dialer) error {
	ctx, cancel := context.WithTimeout(ctx, commandSpeedTestTimeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, speedtest.CustomMagicSocksAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	var downloaded uint32
	err = speedtest.DownloadTest(ctx, conn, commandSpeedTestDataSize, func(duration time.Duration, received uint32, end bool) {
		if end {
			log.Info("download complete:\n downloaded:", received, " speed: ", formatSpeed(received, duration))
			return
		}

		downloaded += received
		log.Info("downloading: downloaded:", downloaded, " speed: ", formatSpeed(received, duration), " progress: ", progress(downloaded, commandSpeedTestDataSize))
	})
	if err != nil {
		return err
	}
	return nil
}

func uploadTest(ctx context.Context, dialer N.Dialer) error {
	ctx, cancel := context.WithTimeout(ctx, commandSpeedTestTimeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, speedtest.CustomMagicSocksAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	var uploaded uint32
	err = speedtest.UploadTest(ctx, conn, commandSpeedTestDataSize, func(duration time.Duration, sent uint32, end bool) {
		if end {
			log.Info("upload complete:\n uploaded:", sent, " speed: ", formatSpeed(sent, duration))
			return
		}

		uploaded += sent
		log.Info("uploading: uploaded:", uploaded, " speed: ", formatSpeed(sent, duration), " progress: ", progress(uploaded, commandSpeedTestDataSize))
	})
	if err != nil {
		return err
	}
	return nil
}

func formatSpeed(bytes uint32, duration time.Duration) string {
	seconds := duration.Seconds()
	if seconds == 0 {
		return "N/A"
	}
	speed := float64(bytes) / seconds
	if commandSpeedTestUseBytes {
		return byteformats.FormatBytes(uint64(speed)) + "/s"
	} else {
		return byteformats.FormatIBytes(uint64(speed)) + "/s"
	}
}

func progress(now, total uint32) string {
	if total == 0 {
		return "0.00%"
	}
	return fmt.Sprintf("%.2f%%", float64(now)/float64(total)*100)
}
