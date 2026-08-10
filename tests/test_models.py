import unittest

from diffsearchvuln.models import RankedCandidate, TournamentDecision


class TournamentDecisionTests(unittest.TestCase):
    def test_accepts_exactly_two_advanced_candidates(self) -> None:
        ranking = tuple(
            RankedCandidate(
                cluster_id=f"candidate-{index}",
                rank=index,
                absolute_score=1.0 - index / 10,
                advanced=index <= 2,
                explanation="evidence",
            )
            for index in range(1, 6)
        )
        decision = TournamentDecision(
            group_id="group-1",
            pass_index=0,
            round_index=0,
            no_strong_candidate=False,
            ranking=ranking,
            model="configured-codex-model",
            prompt_version="1",
        )
        self.assertEqual(2, sum(candidate.advanced for candidate in decision.ranking))

    def test_rejects_non_contiguous_ranks(self) -> None:
        ranking = (
            RankedCandidate("a", 1, 0.9, True, "a"),
            RankedCandidate("b", 3, 0.8, True, "b"),
        )
        with self.assertRaisesRegex(ValueError, "contiguous"):
            TournamentDecision("group", 0, 0, False, ranking, "model", "1")

    def test_rejects_wrong_advanced_count(self) -> None:
        ranking = (
            RankedCandidate("a", 1, 0.9, True, "a"),
            RankedCandidate("b", 2, 0.8, False, "b"),
        )
        with self.assertRaisesRegex(ValueError, "top two"):
            TournamentDecision("group", 0, 0, False, ranking, "model", "1")


if __name__ == "__main__":
    unittest.main()
