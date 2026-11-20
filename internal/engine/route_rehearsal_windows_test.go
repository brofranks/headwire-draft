package engine
import ("fmt";"net";"net/netip";"testing";"time";"os/exec";"io";"slices";"tailscale.com/types/key")
func TestRehearsalWintunSubnet(t *testing.T){
 a:=node{key.NewNode(),netip.MustParsePrefix("fd42::10/128"),freePort(t)}
 b:=node{key.NewNode(),netip.MustParsePrefix("fd42::1a/128"),freePort(t)}
 bc:=b.config(t,"",a,fmt.Sprintf("Endpoint = 127.0.0.1:%d",a.port));bc.Peers[0].DiscoKey=key.DiscoPublic{}
 startEcho(t,bc)
 ac:=a.config(t,"Address = fd42::21/128",b,fmt.Sprintf("Endpoint = 127.0.0.1:%d",b.port));ac.Peers[0].DiscoKey=key.DiscoPublic{}
 ac.Peers[0].AllowedIPs=[]netip.Prefix{netip.MustParsePrefix("fd42::10/124"),netip.MustParsePrefix("fd42::21/128")}
 e,err:=Start(ac,t.Logf,Options{});if err!=nil{t.Fatal(err)};defer e.Close()
 out,err:=exec.Command("powershell","-NoProfile","-Command","$r=Get-NetRoute -InterfaceAlias Headwire -DestinationPrefix 'fd42::10/124' -ErrorAction Stop; $r | Format-Table DestinationPrefix,NextHop,InterfaceIndex").CombinedOutput()
 if err!=nil{t.Fatalf("requested route missing: %v %s",err,out)};t.Log(string(out))
 c,err:=net.DialTimeout("tcp6",fmt.Sprintf("[fd42::1a]:%d",testEchoPort),20*time.Second);if err!=nil{t.Fatal(err)};defer c.Close();c.SetDeadline(time.Now().Add(10*time.Second));msg:=[]byte("addressing-rehearsal");if _,err:=c.Write(msg);err!=nil{t.Fatal(err)};got:=make([]byte,len(msg));if _,err:=io.ReadFull(c,got);err!=nil||!slices.Equal(got,msg){t.Fatal(err,got)}
}
