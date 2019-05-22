package delete

import (
	"os"

	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	api "github.com/weaveworks/eksctl/pkg/apis/eksctl.io/v1alpha5"
	"github.com/weaveworks/eksctl/pkg/authconfigmap"
	"github.com/weaveworks/eksctl/pkg/ctl/cmdutils"
	"github.com/weaveworks/eksctl/pkg/eks"
)

func deleteIAMIdentityMappingCmd(g *cmdutils.Grouping) *cobra.Command {
	p := &api.ProviderConfig{}
	cfg := api.NewClusterConfig()
	var roleFlag string
	cmd := &cobra.Command{
		Use:   "iamidentitymapping <role>",
		Short: "Delete a IAM identity mapping",
		Run: func(cmd *cobra.Command, args []string) {
			if err := doDeleteIAMIdentityMapping(p, cfg, roleFlag, cmdutils.GetNameArg(args)); err != nil {
				logger.Critical("%s\n", err.Error())
				os.Exit(1)
			}
		},
	}
	group := g.New(cmd)

	group.InFlagSet("General", func(fs *pflag.FlagSet) {
		fs.StringVar(&roleFlag, "role", "", "ARN of the IAM role to delete")
		fs.StringVar(&cfg.Metadata.Name, "cluster", "", "EKS cluster name")
	})

	cmdutils.AddCommonFlagsForAWS(group, p, false)

	group.AddTo(cmd)

	return cmd
}

func doDeleteIAMIdentityMapping(p *api.ProviderConfig, cfg *api.ClusterConfig, roleFlag, roleArg string) error {
	ctl := eks.New(p, cfg)

	if err := ctl.CheckAuth(); err != nil {
		return err
	}

	if roleFlag != "" && roleArg != "" {
		return cmdutils.ErrFlagAndArg("--role", roleFlag, roleArg)
	}
	roleFilter := roleFlag
	if roleArg != "" {
		roleFilter = roleArg
	}
	if roleFilter == "" {
		return cmdutils.ErrMustBeSet("--role")
	}
	if cfg.Metadata.Name == "" {
		return cmdutils.ErrMustBeSet("--cluster")
	}

	if err := ctl.GetCredentials(cfg); err != nil {
		return err
	}
	clientSet, err := ctl.NewStdClientSet(cfg)
	if err != nil {
		return err
	}
	acm, err := authconfigmap.NewFromClientSet(clientSet)
	if err != nil {
		return err
	}

	if err := acm.RemoveRole(roleFilter); err != nil {
		return err
	}
	return acm.Save()
}
