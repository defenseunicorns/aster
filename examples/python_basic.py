"""Publish and read exact-key State using an owner-only reference mission file."""
import argparse
from pathlib import Path
from aster_mesh import DataClass, Node, Priority

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("provisioning", type=Path)
parser.add_argument("state", type=Path)
args = parser.parse_args()

with Node(args.state.resolve(), args.provisioning.resolve()) as node:
    node.publish(
        DataClass.STATE, "position.current", "mission/team/alpha",
        b'{"lat":38.9,"lon":-77.0}', operation_key=b"example/position/1",
        logical_key=b"unit-7", priority=Priority.IMMEDIATE,
    )
    with node.query(DataClass.STATE, topic="position.current",
                    scope="mission/team/alpha", logical_key=b"unit-7") as result:
        print(result[0].payload.decode())
