package create

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

func createIAMIdentityMappingCmd(g *cmdutils.Grouping) *cobra.Command {
	p := &api.ProviderConfig{}
	cfg := api.NewClusterConfig()
	id := &authconfigmap.MapRole{}
	cmd := &cobra.Command{
		Use:   "iamidentitymapping <rolearn>",
		Short: "Create an IAM identity mapping",
		Long: `Creates a mapping from IAM role to Kubernetes user and groups.

To create an admin use

    --group=system:masters --username=admin
`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := doCreateIAMIdentityMapping(p, cfg, id, cmdutils.GetNameArg(args)); err != nil {
				logger.Critical("%s\n", err.Error())
				os.Exit(1)
			}
		},
	}
	group := g.New(cmd)

	group.InFlagSet("General", func(fs *pflag.FlagSet) {
		fs.StringVar(&id.RoleARN, "role", "", "ARN of the IAM role to create")
		fs.StringVar(&cfg.Metadata.Name, "cluster", "", "EKS cluster name")
		fs.StringVar(&id.Username, "username", "", "User name within Kubernetes to map to IAM role")
		fs.StringArrayVar(&id.Groups, "group", []string{}, "Group within Kubernetes to which IAM role is mapped")
	})

	cmdutils.AddCommonFlagsForAWS(group, p, false)

	group.AddTo(cmd)

	return cmd
}

func doCreateIAMIdentityMapping(p *api.ProviderConfig, cfg *api.ClusterConfig, id *authconfigmap.MapRole, roleArg string) error {
	ctl := eks.New(p, cfg)

	if err := ctl.CheckAuth(); err != nil {
		return err
	}
	if id.RoleARN != "" && roleArg != "" {
		return cmdutils.ErrFlagAndArg("--role", id.RoleARN, roleArg)
	}
	roleFilter := id.RoleARN
	if roleArg != "" {
		roleFilter = roleArg
	}
	if roleFilter == "" {
		return cmdutils.ErrMustBeSet("--role")
	}
	if cfg.Metadata.Name == "" {
		return cmdutils.ErrMustBeSet("--cluster")
	}
	if err := id.Valid(); err != nil {
		return err
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

	if err := acm.AddRole(roleFilter, id.Username, id.Groups); err != nil {
		return err
	}
	return acm.Save()
}
