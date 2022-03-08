package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"pmu_exporter/exporter"
)

var rootCmd = &cobra.Command{
	Use:   "pmu_exporter",
	Short: "Prometheus exporter for detailed pmu metrics",
	Long:  `Prometheus exporter collecting pmu of the pod.`,
	Run: func(cmd *cobra.Command, args []string) {
		e := exporter.NewExporter(viper.GetString("bind-address"))
		e.RunServer()
	},
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := rootCmd.PersistentFlags()
	flags.StringP("bind-address", "b", "0.0.0.0:9995", "Address to bind to")

	viper.BindPFlags(flags)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initConfig() {
	viper.AutomaticEnv()
}
