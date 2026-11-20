package provider
import("fmt";"net";"net/netip";"slices";"testing";"tailscale.com/net/netmon")
func TestRehearsalAndroidUnderlay(t *testing.T){
 ifs,err:=net.Interfaces();t.Logf("kernel inventory count %d error %v",len(ifs),err)
 defer ClearInterfaces()
 defer netmon.SetTailscaleInterfaceProps("",0)
 netmon.SetTailscaleInterfaceProps("hw-rehearsal",0)
 if name,err:=netmon.TailscaleInterfaceName();err!=nil||name!="hw-rehearsal"{t.Fatal(name,err)}
 for _,a:=range []string{"100.70.1.2","100.70.1.3"}{
  err:=UpdateInterfaces(fmt.Sprintf(`[{"name":"lan","up":true,"index":42,"mtu":1500,"addresses":["%s/24"]},{"name":"hw-rehearsal","up":true,"index":43,"addresses":["100.70.1.9/32"]}]`,a));if err!=nil{t.Fatal(err)}
  ips,_,err:=netmon.LocalAddresses(false);if err!=nil||!slices.Equal(ips,[]netip.Addr{netip.MustParseAddr(a)}){t.Fatal(ips,err)}
  if i,_:=netmon.TailscaleInterfaceIndex();i!=0{t.Fatalf("unexpected kernel index %d",i)}
  t.Logf("eligible endpoints after inventory update: %v",ips)
 }
}
