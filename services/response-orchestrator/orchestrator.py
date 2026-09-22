                        )
                    else:
                        db_verification.verified_at = verification.verified_at
                        db_verification.pre_attack_success_rate = verification.pre_attack_success_rate
                        db_verification.post_attack_success_rate = verification.post_attack_success_rate
                        db_verification.risk_reduction_pct = verification.risk_reduction_pct
                        db_verification.re_simulation_id = verification.re_simulation_id
                        db_verification.continued_indicators = verification.continued_indicators
                        db_verification.monitoring_duration_seconds = verification.monitoring_duration_seconds
                        db_verification.new_alerts_during_monitoring = verification.new_alerts_during_monitoring
                        db_verification.verification_passed = verification.verification_passed
                        db_verification.verdict_reason = verification.verdict_reason


        except RuntimeError as exc:
            if str(exc) != "Database pool has not been initialised":
                raise
            # In-process test fallback when PostgreSQL has not been initialised.
            logger.warning(
                f"Skipping DB persistence for plan {plan.plan_id}: {exc}"
            )
        except Exception as exc:
            logger.error(
                f"Failed to persist defense plan {plan.plan_id}: {exc}"
            )
            # Never report a successful persistence operation when the
            # production database write actually failed.
            raise

    # ----- Main Loop -----

    async def trigger_defense(
        self,
        incident_id: str,
        environment_json: Optional[Dict] = None,
        auto_execute: bool = True,
        dry_run: bool = False,
        skip_simulation: bool = False,
    ) -> DefensePlan:
        """
        Entry point: trigger the full defense loop for an incident.

        1. Fetch incident context from correlation engine
        2. Run simulation (unless skipped)
        3. Generate defense plan
        4. Execute auto-approved actions