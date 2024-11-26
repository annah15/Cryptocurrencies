import telnetlib
import threading
import time
import json

HOST = "localhost"
PORT = 18018

# Define test cases as a list of dictionaries
test_cases = [[
    {
        "description": "Test Hello and Block Validation",
        "send": ['{"agent":"Grader 1","type":"hello","version":"0.10.0"}'],
        "expected_response": ['"type":"hello"', '"type":"getpeers"'],
    },
    {
        "description": "Test Block Transmission and Validation",
        "send": ['{"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671062400,"miner":"Marabu","nonce":"000000000000000000000000000000000000000000000000000000021bea03ed","note":"The New York Times 2022-12-13: Scientists Achieve Nuclear Fusion Breakthrough With Blast of 192 Lasers","previd":null,"txids":[],"type":"block"},"type":"object"}'],
        "expected_response": [],
    },
    {
        "description": "Test Block Request and Response",
        "send": ['{"objectid":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2","type":"getobject"}'],
        "expected_response": ['{"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671062400,"miner":"Marabu","nonce":"000000000000000000000000000000000000000000000000000000021bea03ed","note":"The New York Times 2022-12-13: Scientists Achieve Nuclear Fusion Breakthrough With Blast of 192 Lasers","previd":null,"txids":[],"type":"block"},"type":"object"}'],
    },
    {
        "description": "Test Block sending with missing Object",
        "send": ['{"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671148800,"miner":"grader","nonce":"100000000000000000000000000000000000000000000000000000002fe1b1b2","note":"This block has a coinbase transaction","previd":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2","txids":["54e4ba53bb15fde319ca643c6e88fc9b550ef7071bd7765e3220d8b1b3a206a5"],"type":"block"},"type":"object"}'],
        "expected_response": ['{"objectid":"54e4ba53bb15fde319ca643c6e88fc9b550ef7071bd7765e3220d8b1b3a206a5","type":"getobject"}'],
    },
    {
        "description": "Test IhaveObject",
        "send": ['{"object":{"height":1,"outputs":[{"pubkey":"b9a98a6d2b211f69d1a39873c6df6646fe850cdf1a46d286a95f673834957129","value":50000000000000}],"type":"transaction"},"type":"object"}'],
        "expected_response": ['{"objectid":"54e4ba53bb15fde319ca643c6e88fc9b550ef7071bd7765e3220d8b1b3a206a5","type":"ihaveobject"}', '{"objectid":"000000009592aa012d286444fce5fd9620b04ed4259f3a36dfd378830b488c93","type":"ihaveobject"}'],
    },
    {
        "description": "Test Object exists",
        "send": ['{"objectid":"000000009592aa012d286444fce5fd9620b04ed4259f3a36dfd378830b488c93","type":"getobject"}'],
        "expected_response": ['{"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671148800,"miner":"grader","nonce":"100000000000000000000000000000000000000000000000000000002fe1b1b2","note":"This block has a coinbase transaction","previd":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2","txids":["54e4ba53bb15fde319ca643c6e88fc9b550ef7071bd7765e3220d8b1b3a206a5"],"type":"block"},"type":"object"}'],
    },
    {
        "description": "Test sending Block with missing Transactions",
        "send": ['{"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671280061,"miner":"grader","nonce":"31b15f98bc991e854cc5619baaab3ea2cb8c4cf2bb0cac8f6bca7e1e8093ea8d","note":"This block has another coinbase and spends earlier coinbase","previd":"000000009592aa012d286444fce5fd9620b04ed4259f3a36dfd378830b488c93","txids":["8afa811d1a2d1cf92271b800838a7a8afd8b3b6061c609087f3d24dd39aa3725","938fefc38d59fb7fc81458436664937dd57a6d876de9107fb682643f7c978897"],"type":"block"},"type":"object"}'],
        "expected_response": ['{"objectid":"938fefc38d59fb7fc81458436664937dd57a6d876de9107fb682643f7c978897","type":"getobject"}','{"objectid":"8afa811d1a2d1cf92271b800838a7a8afd8b3b6061c609087f3d24dd39aa3725","type":"getobject"}'],
    },
    {
        "description": "Test getting Ihaveobj",
        "send": ['{"object":{"height":2,"outputs":[{"pubkey":"bc6b5ba2fd71fdfe7fec073fabf8467db7c30367a052238692d2511b60361348","value":51000000000000}],"type":"transaction"},"type":"object"}', '{"object":{"inputs":[{"outpoint":{"index":0,"txid":"54e4ba53bb15fde319ca643c6e88fc9b550ef7071bd7765e3220d8b1b3a206a5"},"sig":"8895e8000ee7ad71d1e89a3e01284aa2b4e20a8532af3e05ca8369bbced725c7bf3c5558c1b9871948e564cbcf0e4b9a141a578826df70eece72e8c6cb834408"}],"outputs":[{"pubkey":"df59dda870bb10fc09ddc5ae62045a017f6f0dc28a6a886b39853716794cf669","value":49000000000000}],"type":"transaction"},"type":"object"}'],
        "expected_response": ['{"objectid":"8afa811d1a2d1cf92271b800838a7a8afd8b3b6061c609087f3d24dd39aa3725","type":"ihaveobject"}', '{"objectid":"938fefc38d59fb7fc81458436664937dd57a6d876de9107fb682643f7c978897","type":"ihaveobject"}', '{"objectid":"00000000aaeb3e3620419db86d02ba79792082c3403feebd86334fd48bbe6e35","type":"ihaveobject"}'],
    },
    {
        "description": "Test get just send Block",
        "send": ['{"objectid":"00000000aaeb3e3620419db86d02ba79792082c3403feebd86334fd48bbe6e35","type":"getobject"}'],
        "expected_response": ['{"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671280061,"miner":"grader","nonce":"31b15f98bc991e854cc5619baaab3ea2cb8c4cf2bb0cac8f6bca7e1e8093ea8d","note":"This block has another coinbase and spends earlier coinbase","previd":"000000009592aa012d286444fce5fd9620b04ed4259f3a36dfd378830b488c93","txids":["8afa811d1a2d1cf92271b800838a7a8afd8b3b6061c609087f3d24dd39aa3725","938fefc38d59fb7fc81458436664937dd57a6d876de9107fb682643f7c978897"],"type":"block"},"type":"object"}'],
    },
    {
        "description": "Test Send invalid proof of work block and do not gossip invalid block.",
        "send": ['{"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671148915,"miner":"grader","nonce":"275adb0f18f8a1bec8d1350e653976a9cead9b6132bb95a8bc2a0e8f8746e0ac","note":"Block with invalid PoW","previd":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2","txids":[],"type":"block"},"type":"object"}'],
        "expected_response": ['"name":"INVALID_BLOCK_POW","type":"error"'],
    }],[
    {
        "description": "Test Block has incorrect target.",
        "send": ['{"agent":"Grader 1","type":"hello","version":"0.10.0"}', '{"object":{"T":"00b0000000000000000000000000000000000000000000000000000000000000","created":1671355937,"miner":"grader","nonce":"600000000000000000000000000000000000000000000000000000000000004d","note":"Block with incorrect target","previd":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2","txids":[],"type":"block"},"type":"object"}'],
        "expected_response": ['"type":"hello"', '"type":"getpeers"', '"name":"INVALID_FORMAT","type":"error"' ],
    }],[
    {
        "description": "Test Block has invalid proof-of-work.",
        "send": ['{"agent":"Grader 1","type":"hello","version":"0.10.0"}', '{"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671356958,"miner":"grader","nonce":"90000000000000000000000000000000000000000000000000000000012baaaa","note":"Block with invalid PoW","previd":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2","txids":[],"type":"block"},"type":"object"}'],
        "expected_response": ['"type":"hello"', '"type":"getpeers"', '"name":"INVALID_BLOCK_POW","type":"error"'],
    }],[
    {
        "description": "Test Block sending Block with missing transactions.",
        "send": ['{"agent":"Grader 1","type":"hello","version":"0.10.0"}', '{"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671469958,"miner":"grader","nonce":"bc0c16cc1547c056cd1397e95ce4902faa055789842648584a5022a06bb32199","note":"This block has a coinbase transaction","previd":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2","txids":["7d1ddab9e04e3ccb00ef390de7529a75635509ed20d64fc25080e4f7015d9e41"],"type":"block"},"type":"object"}'],
        "expected_response": ['"type":"hello"', '"type":"getpeers"', '{"objectid":"7d1ddab9e04e3ccb00ef390de7529a75635509ed20d64fc25080e4f7015d9e41","type":"getobject"}'],
    },
    {
        "description": "Test supply missing transactions.",
        "send": ['{"object":{"height":1,"outputs":[{"pubkey":"5552c0b356c460c14c403185e8882da5bd8c8b68bfca7b06f5c684d108ca4d15","value":50000000000000}],"type":"transaction"},"type":"object"}'],
        "expected_response": ['{"objectid":"7d1ddab9e04e3ccb00ef390de7529a75635509ed20d64fc25080e4f7015d9e41","type":"ihaveobject"}', '{"objectid":"0000000000af29dc5a3ff69b6304abbc29e9259c2338d294da21d41ee1af10c9","type":"ihaveobject"}'],
    },
    {
        "description": "Test check if block is there.",
        "send": ['{"objectid":"0000000000af29dc5a3ff69b6304abbc29e9259c2338d294da21d41ee1af10c9","type":"getobject"}'],
        "expected_response": ['{"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671469958,"miner":"grader","nonce":"bc0c16cc1547c056cd1397e95ce4902faa055789842648584a5022a06bb32199","note":"This block has a coinbase transaction","previd":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2","txids":["7d1ddab9e04e3ccb00ef390de7529a75635509ed20d64fc25080e4f7015d9e41"],"type":"block"},"type":"object"}'],
    },
    {
        "description": "Test Block sending Block with missing transactions.",
        "send": ['{"object":{"T":"00000000abc00000000000000000000000000000000000000000000000000000","created":1671470413,"miner":"grader","nonce":"60000000000000000000000000000000000000000000000000000000681fd40e","note":"This block violates the law of conservation","previd":"0000000000af29dc5a3ff69b6304abbc29e9259c2338d294da21d41ee1af10c9","txids":["52985dda6470b8c12f6e5112ee2467d014d8448fe93f9f39652b8533dae6b607","c34edb783cd4b5330ba4eb41fab22515f18f1c2d40b7da43d061164f2d1efea7"],"type":"block"},"type":"object"}'],
        "expected_response": ['{"objectid":"52985dda6470b8c12f6e5112ee2467d014d8448fe93f9f39652b8533dae6b607","type":"getobject"}', '{"objectid":"c34edb783cd4b5330ba4eb41fab22515f18f1c2d40b7da43d061164f2d1efea7","type":"getobject"}'],
    },
    {
        "description": "Test supply missing transactions.",
        "send": ['{"object":{"height":2,"outputs":[{"pubkey":"70df8e8bd5d066d98fbef557832383879d3499a39e7d35d21ac901273fcaf036","value":80000000000000}],"type":"transaction"},"type":"object"}', '{"object":{"inputs":[{"outpoint":{"index":0,"txid":"7d1ddab9e04e3ccb00ef390de7529a75635509ed20d64fc25080e4f7015d9e41"},"sig":"8266ad60532a12ea49430cafc438af1f7b793275484d21545bf06fdf2220e61f9cb1daa5cfb5453d055ad94144eb7b95ad4fc2a18f9da8cd4e1dd661c991cc0b"}],"outputs":[{"pubkey":"260270b6d9fdfcc6d4aed967915ef64d67973e98f9f2216981c603c967608806","value":40000000000000}],"type":"transaction"},"type":"object"}'],
        "expected_response": ['{"objectid":"7d1ddab9e04e3ccb00ef390de7529a75635509ed20d64fc25080e4f7015d9e41","type":"ihaveobject"}', '{"objectid":"0000000000af29dc5a3ff69b6304abbc29e9259c2338d294da21d41ee1af10c9","type":"ihaveobject"}'],
    },
    {
        "description": "Test Block does not satisfy coinbase law of conservation.",
        "send": ['{"objectid":"0000000000af29dc5a3ff69b6304abbc29e9259c2338d294da21d41ee1af10c9","type":"getobject"}'],
        "expected_response": ['"name":"INVALID_BLOCK_COINBASE","type":"error"'],
    }]
    # Additional test cases can be added here...
]

def receive_messages(tn, response_list):
    """Receives messages from the server and adds them to a shared list."""
    while True:
        try:
            response = tn.read_until(b'\n', timeout=2).decode('utf-8').strip()
            if response:
                response_list.append(response)
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def run_test_case(tn, case, response_list):
    """Sends a message, waits for a response, and checks the expected result."""
    print(f"\nRunning Test: {case['description']}")
    for msg in case['send']:
        tn.write(msg.encode('utf-8') + b'\n')  # Send the message
        print(f"Sent: {msg}")

    time.sleep(1)  # Wait for the server's response
    if response_list:
        for rsp in case["expected_response"]:
            received = response_list.pop(0)  # Retrieve the first received message
            print(f"Received: {received}")
            if rsp in received:
                print("Test PASSED")
            else:
                print("Test FAILED: Unexpected response")

def main():
    try:
        for test_case in test_cases:
            with telnetlib.Telnet(HOST, PORT) as tn:
                print(f"Connected to {HOST}:{PORT}")
                
                # Shared list for storing responses
                response_list = []
                
                # Start a thread for receiving messages
                receiver_thread = threading.Thread(target=receive_messages, args=(tn, response_list), daemon=True)
                receiver_thread.start()

                # Run each test case
                for test in test_case:
                    run_test_case(tn, test, response_list)
                    time.sleep(1)  # Brief pause between test cases
                
                print("\nAll tests completed.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()