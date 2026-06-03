"""
evolution_engine.py — Gatekeeper wrapping the NovaGlyph Evolution Engine pattern.

The Evolution Engine is a generative loop that proposes mutations to a
"concept grid" (64-byte NovaGlyph plane) and evolves the best candidates.
Because the engine can propose destructive or irreversible mutations, every
proposed generation step is gated by the Gatekeeper Protocol before it
executes.

Architecture:
    EvolutionEngine.generate_candidates()
        → for each candidate: GatekeeperSession.propose()
        → GatekeeperSession.request_authorization()   ← human in the loop
        → on approval: candidate is applied and logged
        → on denial:   candidate is discarded, engine tries next

This mirrors the CREATE + DECIDE plane interaction in the NovaGlyph stack:
    CREATE plane proposes → DECIDE plane scores → human gates via Gatekeeper
    → LEARN plane records outcome for the next cycle.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))
from gatekeeper import GatekeeperSession, GatekeeperError

# ── NovaGlyph concept-plane types ─────────────────────────────────────────────

@dataclass
class ConceptPlane:
    """64-byte NovaGlyph concept grid — one plane of the POLYGRID."""
    bytes_: bytearray = field(default_factory=lambda: bytearray(64))
    generation: int = 0

    def as_bytes(self) -> bytes:
        return bytes(self.bytes_)

    def summary(self) -> str:
        active = sum(1 for b in self.bytes_ if b != 0)
        return (
            f"ConceptPlane(gen={self.generation}, "
            f"active={active}/64, "
            f"hash={hashlib.sha256(self.as_bytes()).hexdigest()[:12]}…)"
        )


@dataclass
class Mutation:
    """A proposed mutation to one or more bytes of the concept plane."""
    description: str
    byte_index: int
    old_value: int
    new_value: int
    score: float          # DECIDE-plane score (0.0–1.0)
    rationale: str

    def apply(self, plane: ConceptPlane) -> ConceptPlane:
        """Return a new plane with this mutation applied (non-destructive)."""
        new_plane = ConceptPlane(
            bytes_=bytearray(plane.bytes_),
            generation=plane.generation + 1,
        )
        new_plane.bytes_[self.byte_index] = self.new_value
        return new_plane

    def to_payload(self) -> bytes:
        """Canonical byte representation of this mutation for signing."""
        record = {
            "description": self.description,
            "byte_index":  self.byte_index,
            "old_value":   self.old_value,
            "new_value":   self.new_value,
            "score":       self.score,
            "rationale":   self.rationale,
        }
        return json.dumps(record, separators=(",", ":"), sort_keys=True).encode()


# ── Simulated CREATE plane ─────────────────────────────────────────────────────

class CreatePlane:
    """
    Simulates the NovaGlyph CREATE plane — generates candidate mutations.

    In production this would be driven by the lightc compiler + local Ollama.
    Here it generates plausible candidates for demonstration purposes.
    """

    # Concept grid byte meanings (first 8 concepts from the NovaGlyph 64-concept grid)
    CONCEPT_NAMES = {
        0: "THINK",  1: "FEEL",  2: "SENSE",  3: "MOVE",
        4: "SPEAK",  5: "LEARN", 6: "CREATE", 7: "DECIDE",
    }

    def generate(self, plane: ConceptPlane, n: int = 3) -> list[Mutation]:
        """Generate up to n candidate mutations for the current plane state."""
        import random
        rng = random.Random(int.from_bytes(plane.as_bytes()[:4], "big") ^ int(time.time()))

        candidates = []
        for _ in range(n):
            idx = rng.randint(0, 63)
            old_val = plane.bytes_[idx]
            # Evolve toward higher activation (closer to 0xFF) with some noise
            delta = rng.randint(1, 32)
            new_val = min(255, old_val + delta)
            if new_val == old_val:
                continue
            concept = self.CONCEPT_NAMES.get(idx, f"concept_{idx:02d}")
            score = round(rng.uniform(0.4, 0.95), 3)
            candidates.append(Mutation(
                description=f"Strengthen {concept} activation: {old_val:#04x} → {new_val:#04x}",
                byte_index=idx,
                old_value=old_val,
                new_value=new_val,
                score=score,
                rationale=(
                    f"DECIDE plane scores {score:.1%} fitness for this cycle. "
                    f"Reinforces the {concept} concept based on recent LEARN log."
                ),
            ))

        # Sort by DECIDE score, highest first
        candidates.sort(key=lambda m: m.score, reverse=True)
        return candidates


# ── Evolution engine ──────────────────────────────────────────────────────────

class EvolutionEngine:
    """
    Generative evolution loop with Gatekeeper-enforced human authorisation.

    Each cycle:
      1. CREATE plane generates N candidate mutations.
      2. For each candidate (highest score first):
         a. Gatekeeper proposes the mutation to the human operator.
         b. On AUTHORIZE: mutation is applied, token stored in audit log.
         c. On DENY:      mutation is discarded, engine tries the next one.
         d. If all candidates denied: cycle ends without mutation.
    """

    def __init__(
        self,
        plane: Optional[ConceptPlane] = None,
        keyfile: Optional[str] = None,
        auto_approve: bool = False,
    ):
        self.plane     = plane or ConceptPlane()
        self.session   = GatekeeperSession(keyfile=keyfile)
        self.create    = CreatePlane()
        self._tokens: list[dict] = []
        self._auto_approve = auto_approve  # for non-interactive demo/testing

    def run_cycle(self, candidates_per_cycle: int = 3) -> bool:
        """
        Run one evolution cycle. Returns True if a mutation was applied.
        """
        print(f"\n{'='*70}")
        print(f"EVOLUTION CYCLE  plane={self.plane.summary()}")
        print(f"{'='*70}")

        candidates = self.create.generate(self.plane, n=candidates_per_cycle)
        if not candidates:
            print("CREATE plane: no candidates generated this cycle.")
            return False

        print(f"CREATE plane generated {len(candidates)} candidate(s):")
        for i, m in enumerate(candidates):
            print(f"  [{i+1}] score={m.score:.1%}  {m.description}")

        for mutation in candidates:
            payload = mutation.to_payload()
            description = (
                f"Evolution Engine: {mutation.description}\n"
                f"  Score: {mutation.score:.1%} | "
                f"Rationale: {mutation.rationale}"
            )
            action = self.session.propose(description, payload)

            if self._auto_approve:
                # Non-interactive mode: simulate approval (demo/testing only)
                token = self.session.sign_token_for_test_if_available(action)
                if token is None:
                    token = self._simulate_approve(action, payload)
            else:
                token = self.session.request_authorization(action)

            if token:
                # Verify before applying (defence-in-depth)
                if not self.session.verify(token, payload):
                    print("WARNING: token failed verification — skipping mutation.")
                    continue

                self.plane = mutation.apply(self.plane)
                self._tokens.append(token)

                print(f"\nMutation applied. New plane: {self.plane.summary()}")
                print(f"AuthToken action_id: {token['action_id'][:16]}…")
                return True
            else:
                print(f"Mutation denied by operator — trying next candidate.")

        print("All candidates denied this cycle. Plane unchanged.")
        return False

    def _simulate_approve(self, action: dict, payload: bytes) -> dict:
        """Auto-approve path for demo mode (not for production use)."""
        # Build a minimal valid token via the Python session internals
        approved_at = int(time.time())
        return self.session._py_sign_token(action, approved_at)

    def run(self, cycles: int = 3, candidates_per_cycle: int = 3) -> None:
        """Run multiple evolution cycles."""
        applied = 0
        for cycle in range(1, cycles + 1):
            print(f"\n[CYCLE {cycle}/{cycles}]")
            if self.run_cycle(candidates_per_cycle):
                applied += 1

        print(f"\n{'='*70}")
        print(f"EVOLUTION COMPLETE")
        print(f"  Cycles run:         {cycles}")
        print(f"  Mutations applied:  {applied}")
        print(f"  Final plane:        {self.plane.summary()}")
        print(f"  Approver pubkey:    {self.session.pubkey_hex() or '(CLI mode)'}")
        print(f"  Audit entries:      {len(self.session.audit_trail())}")
        print(f"{'='*70}")

    @property
    def audit_trail(self) -> list[dict]:
        return self.session.audit_trail()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="NovaGlyph Evolution Engine — Gatekeeper-gated generative loop"
    )
    parser.add_argument("--cycles",     type=int, default=2,
                        help="Number of evolution cycles to run (default: 2)")
    parser.add_argument("--candidates", type=int, default=3,
                        help="Candidate mutations per cycle (default: 3)")
    parser.add_argument("--keyfile",    type=str, default=None,
                        help="Path to persistent Ed25519 keyfile")
    parser.add_argument("--auto",       action="store_true",
                        help="Auto-approve all mutations (demo mode, NOT for production)")
    args = parser.parse_args()

    if args.auto:
        print("WARNING: --auto mode bypasses human authorisation. Demo only.")

    engine = EvolutionEngine(
        keyfile=args.keyfile,
        auto_approve=args.auto,
    )
    engine.run(cycles=args.cycles, candidates_per_cycle=args.candidates)

    # Export audit trail
    audit = engine.audit_trail
    if audit:
        print(f"\nAudit trail ({len(audit)} entries):")
        for e in audit:
            outcome = e["outcome"]["outcome"]
            desc = e["action"]["description"].split("\n")[0]
            print(f"  {outcome:10s}  {desc[:60]}")
