// Offline exact-key State publication through the selected-node C ABI.
package main

import (
	aster "defenseunicorns.com/aster/mesh"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: %s PROVISIONING_FILE STATE_DIRECTORY", os.Args[0])
	}
	mission, err := filepath.Abs(os.Args[1])
	if err != nil {
		return err
	}
	state, err := filepath.Abs(os.Args[2])
	if err != nil {
		return err
	}
	node, err := aster.Open(state, mission)
	if err != nil {
		return err
	}
	defer node.Close()
	_, err = node.Publish(aster.PublishRequest{Class: aster.State, Topic: "position.current", Scope: "mission/team/alpha", OperationKey: []byte("example/position/1"), LogicalKey: []byte("unit-7"), Payload: []byte(`{"lat":38.9,"lon":-77.0}`), Priority: aster.Immediate})
	if err != nil {
		return err
	}
	result, err := node.Query(aster.Query{Class: aster.State, Topic: "position.current", Scope: "mission/team/alpha", LogicalKey: []byte("unit-7")})
	if err != nil {
		return err
	}
	defer result.Close()
	fmt.Println(string(result.Items[0].Payload))
	return nil
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
