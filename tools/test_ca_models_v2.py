"""Structural checks for the added acceptance/query contract, no verifier run."""
import unittest
from tools import run_ca_models_v2 as models


class CompositeContract(unittest.TestCase):
    def test_every_scenario_uses_received_flight_in_online_checks(self):
        for name, options in models.SCENARIOS.items():
            with self.subTest(name=name):
                source = models.model(name, options)
                self.assertIn("serverAuthentication = CONCAT(serverHello, certificateTranscript, onlineSignature, onlineAltSignature, serverFinished)", source)
                self.assertIn("= SPLIT(serverAuthentication)?", source)
                self.assertIn("ASSERT(receivedCertificateTranscript, CONCAT(leafTBS, leafSig, leafAltSig))?", source)
                self.assertIn("ASSERT(receivedOnlineSignature, onlineSignature)?", source)
                self.assertIn("SIGNVERIF(flightOnlineClassicalPk, cvClient, receivedOnlineSignature)?", source)
                self.assertIn("DH_KEX(receivedServerShare, clientEphemeral)", source)
                self.assertIn("KEM_DECAP(clientKemSecret, receivedKemCiphertext)", source)
                self.assertIn("ASSERT(receivedServerFinished, MAC(finishedKeyClient, HASH(transcriptClient, receivedOnlineSignature, receivedOnlineAltSignature)))?", source)
                self.assertEqual("SIGNVERIF(receivedIntermediateAltPk, flightTBS, flightAlternativeSig)?" in source, options[0])
                self.assertEqual("SIGNVERIF(flightOnlineAltPk, cvClient, receivedOnlineAltSignature)?" in source, options[3])

    def test_queries_are_all_acceptance_conditioned_and_separate(self):
        source = models.model("M1_honest", models.SCENARIOS["M1_honest"])
        queries = source.rsplit("queries[", 1)[1]
        self.assertEqual(queries.count("precondition[Client -> Server: appRecord]"), 5)
        self.assertIn("authentication? Server -> Client: onlineSignature[", queries)
        self.assertIn("authentication? Server -> Client: serverAuthentication[", queries)
        self.assertEqual(len(models.QUERY_MAP), 5)

    def test_no_expected_result_codes_or_mutation_of_v1(self):
        self.assertNotEqual(models.MODELS, models.v1.MODELS)
        self.assertEqual(models.v1.model("M1_honest", models.SCENARIOS["M1_honest"]).count("serverAuthentication"), 0)


if __name__ == "__main__":
    unittest.main()
