/**
 * Durations written the way the rest of the stack writes them: a number of
 * seconds, or a string such as `'180 days'`, `'1 minute'` or `'30s'`.
 *
 * The rules are the ones every duration in the framework follows, so a value
 * moved over from another config file means the same thing here:
 *
 *  - A **number is seconds** and passes through.
 *  - A **string without a unit is milliseconds** (`'7200'` is 7.2 seconds).
 *  - A zero or unreadable string is refused rather than read as zero.
 *
 * Duplicated rather than imported: blackhole depends on no other package of
 * the workspace.
 */

const DURATION_PATTERN =
	/^(-?(?:\d+)?\.?\d+) *(m(?:illiseconds?|s(?:ecs?)?))?(s(?:ec(?:onds?|s)?)?)?(m(?:in(?:utes?|s)?)?)?(h(?:ours?|rs?)?)?(d(?:ays?)?)?(w(?:eeks?|ks?)?)?(y(?:ears?|rs?)?)?$/;

const SECOND = 1000;
const MINUTE = SECOND * 60;
const HOUR = MINUTE * 60;
const DAY = HOUR * 24;
const YEAR = DAY * 365.25;

/** A duration string as milliseconds, or `undefined` when it is not one. */
function parseDurationMs(value: string): number | undefined {
	const matched = DURATION_PATTERN.exec(value.trim().toLowerCase());
	if (matched === null) return undefined;
	const amount = Number.parseFloat(matched[1] ?? "");
	if (!amount) return undefined;
	if (matched[3] !== undefined) return amount * SECOND;
	if (matched[4] !== undefined) return amount * MINUTE;
	if (matched[5] !== undefined) return amount * HOUR;
	if (matched[6] !== undefined) return amount * DAY;
	if (matched[7] !== undefined) return amount * DAY * 7;
	if (matched[8] !== undefined) return amount * YEAR;
	return amount;
}

/**
 * A duration as whole seconds (rounded down).
 *
 * @param label - what is being read, for the error message.
 * @throws When the value is not a finite, non-negative duration.
 */
export function durationToSeconds(
	value: number | string,
	label: string,
): number {
	const seconds =
		typeof value === "number"
			? value
			: (parseDurationMs(value) ?? Number.NaN) / SECOND;
	if (!Number.isFinite(seconds) || seconds < 0) {
		throw new Error(
			`[blackhole] Cannot read ${JSON.stringify(value)} as ${label}: use a non-negative number of seconds, or a duration such as '30s', '1 minute' or '180 days'.`,
		);
	}
	return Math.floor(seconds);
}
