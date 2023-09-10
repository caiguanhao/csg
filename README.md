# csg

China Southern Power Grid (中国南方电网) API

[Docs](https://pkg.go.dev/github.com/caiguanhao/csg)

```go
import "github.com/caiguanhao/csg"
ctx := context.Background()
client, err := csg.Login(ctx, "phone", "password")
accounts, err := client.GetAccounts(ctx)
bills, err := client.GetBills(ctx, accounts[0], 2023)
accounts2, err := client.GetAccountsWithMeteringPointId(ctx, accounts[0])
usages, err := client.GetDailyUsages(ctx, accounts2[0], 2023, 9)
```

Reference: [china_southern_power_grid_stat](https://github.com/CubicPill/china_southern_power_grid_stat)
