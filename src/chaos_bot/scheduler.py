"""Randomized interval scheduler for chaos-bot modules."""

import random
import time
from typing import Callable

from chaos_bot.logger import get_logger


def run_once(modules: dict[str, Callable], targets: list[str], config: dict,
             stop_event=None) -> list[dict]:
    """Run all enabled modules once against targets, return results."""
    log = get_logger()
    results = []
    module_names = list(modules.keys())
    random.shuffle(module_names)

    schedule = config.get("schedule", {})
    delay_min = schedule.get("module_delay_min", 5)
    delay_max = schedule.get("module_delay_max", 30)

    for name in module_names:
        if stop_event and stop_event.is_set():
            log.info("Stop event received, aborting run", extra={"bot_module": "scheduler"})
            break

        mod_cfg = config.get("modules", {}).get(name, {})
        if not mod_cfg.get("enabled", True):
            log.info(f"Skipping disabled module: {name}", extra={"bot_module": name})
            continue

        log.info(f"Running module: {name}", extra={"bot_module": name})
        try:
            module = modules[name]
            result = module.run(targets)
            result["module"] = name
            results.append(result)
            log.info(
                f"Module {name} completed: {result.get('status', 'unknown')}",
                extra={"bot_module": name},
            )
        except Exception as e:
            log.error(f"Module {name} failed: {e}", extra={"bot_module": name}, exc_info=True)
            results.append({"module": name, "status": "error", "message": str(e)})

        # Jitter between modules (skip after last)
        if name != module_names[-1]:
            delay = random.uniform(delay_min, delay_max)
            log.debug(f"Sleeping {delay:.1f}s before next module", extra={"bot_module": "scheduler"})
            if stop_event:
                stop_event.wait(timeout=delay)
            else:
                time.sleep(delay)

    return results


def run_daemon(modules: dict[str, Callable], targets: list[str], config: dict,
               stop_event=None) -> None:
    """Run modules in a loop with randomized intervals until stopped."""
    log = get_logger()
    schedule = config.get("schedule", {})
    cooldown_min = schedule.get("cooldown_min", 30)
    cooldown_max = schedule.get("cooldown_max", 120)

    cycle = 0
    while True:
        if stop_event and stop_event.is_set():
            log.info("Stop event received, exiting daemon loop", extra={"bot_module": "scheduler"})
            break

        cycle += 1
        log.info(f"Starting cycle {cycle}", extra={"bot_module": "scheduler"})
        run_once(modules, targets, config)

        cooldown = random.uniform(cooldown_min, cooldown_max)
        log.info(f"Cycle {cycle} complete, cooldown {cooldown:.1f}s", extra={"bot_module": "scheduler"})

        if stop_event:
            stop_event.wait(timeout=cooldown)
        else:
            time.sleep(cooldown)
