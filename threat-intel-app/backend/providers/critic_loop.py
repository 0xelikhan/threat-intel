"""
Generator/critic loop on top of LLMProvider.

Adapted from Cisco Talos PEAK-Assistant (MIT licensed; copyright 2025
Cisco Systems, Inc.). PEAK uses autogen-agentchat's RoundRobinGroupChat
to pair a generator agent with a critic that emits a termination token
when the output is acceptable. We don't want a second multi-agent
framework alongside LangGraph, so the loop is reimplemented here as a
plain async function over the existing LLMProvider abstraction.

Shape:
  draft  = generator(messages)
  while iters < max_iters:
      feedback = critic(draft)
      if TERMINATE_TOKEN in feedback: return draft
      draft = generator(messages + critic_feedback)
  return draft  # best-effort after max_iters

Callers supply only the system prompts; everything else (provider, model
override, max_tokens, temperature, termination token) lives behind one
call site. No state persists between invocations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .base import LLMProvider, Message


DEFAULT_TERMINATION_TOKEN = "YYY-TERMINATE-YYY"


@dataclass
class CriticLoopResult:
    """What the loop produced. `iterations` counts how many generator runs
    happened (1 = no critic feedback was needed). `terminated_cleanly` is
    True when the critic emitted the termination token before max_iters."""
    output:              str  = ""
    iterations:          int  = 0
    terminated_cleanly:  bool = False
    error:               Optional[str] = None
    critic_feedback:     List[str] = field(default_factory=list)


async def run_critic_loop(
    *,
    provider:            LLMProvider,
    generator_system:    str,
    critic_system:       str,
    user_content:        str,
    max_iters:           int = 2,
    termination_token:   str = DEFAULT_TERMINATION_TOKEN,
    temperature:         float = 0.2,
    max_tokens:          Optional[int] = 900,
    model:               Optional[str] = None,
) -> CriticLoopResult:
    """Run a generator/critic loop and return the final draft.

    `max_iters` is the cap on TOTAL generator runs (initial draft + one
    revision when max_iters=2). The critic always runs once per generator
    pass to decide whether to accept; on the final pass we skip the critic
    since there's no chance to revise.
    """

    base_messages: List[Message] = [
        {"role": "system", "content": generator_system},
        {"role": "user",   "content": user_content},
    ]

    kwargs = {"model": model} if model else {}

    feedback_history: List[str] = []
    draft = ""
    last_err: Optional[str] = None

    for iteration in range(1, max_iters + 1):
        gen_messages = list(base_messages)
        for fb in feedback_history:
            gen_messages.append({"role": "user",
                                 "content": f"Critic feedback to address:\n{fb}"})
        gen_resp = await provider.complete(
            messages=gen_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        if gen_resp.error:
            last_err = gen_resp.error
            break
        draft = (gen_resp.message or "").strip()

        if iteration == max_iters:
            # No room left to revise — return what we have. Caller can
            # decide whether to surface "best-effort, not critic-approved".
            return CriticLoopResult(
                output=draft, iterations=iteration,
                terminated_cleanly=False, critic_feedback=feedback_history,
            )

        critic_messages: List[Message] = [
            {"role": "system", "content": critic_system},
            {"role": "user",   "content":
                f"Draft to evaluate:\n\n{draft}\n\nReturn '{termination_token}' on a "
                f"line by itself if the draft meets every criterion. Otherwise return "
                f"specific, actionable feedback for the next revision."},
        ]
        critic_resp = await provider.complete(
            messages=critic_messages,
            temperature=0.1,
            max_tokens=400,
            **kwargs,
        )
        if critic_resp.error:
            # Critic failed — return the current draft rather than retrying.
            return CriticLoopResult(
                output=draft, iterations=iteration,
                terminated_cleanly=False, critic_feedback=feedback_history,
                error=f"critic call failed: {critic_resp.error}",
            )
        critic_msg = (critic_resp.message or "").strip()
        if termination_token in critic_msg:
            return CriticLoopResult(
                output=draft, iterations=iteration,
                terminated_cleanly=True, critic_feedback=feedback_history,
            )
        feedback_history.append(critic_msg)

    return CriticLoopResult(
        output=draft, iterations=max_iters,
        terminated_cleanly=False, critic_feedback=feedback_history,
        error=last_err,
    )
