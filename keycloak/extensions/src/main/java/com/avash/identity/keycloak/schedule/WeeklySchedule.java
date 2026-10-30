package com.avash.identity.keycloak.schedule;

import java.time.DayOfWeek;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Weekly access window in the gateway's attribute format (see Identity.Contracts.WeeklySchedule):
 * {@code unrestricted}, or {@code sat=08:00-16:00;sun=08:00-12:00,14:00-18:00}. A day that is not listed has
 * no access; ends are exclusive and {@code 24:00} ends a day. Both implementations must stay in line.
 */
public final class WeeklySchedule {

    public static final String ATTRIBUTE = "access.schedule";
    public static final WeeklySchedule UNRESTRICTED = new WeeklySchedule(true, new EnumMap<>(DayOfWeek.class));

    private static final Map<String, DayOfWeek> DAYS = Map.of(
            "sat", DayOfWeek.SATURDAY, "sun", DayOfWeek.SUNDAY, "mon", DayOfWeek.MONDAY, "tue", DayOfWeek.TUESDAY,
            "wed", DayOfWeek.WEDNESDAY, "thu", DayOfWeek.THURSDAY, "fri", DayOfWeek.FRIDAY);

    /** Minutes after midnight; the end is exclusive. */
    record Range(int start, int end) {
    }

    private final boolean unrestricted;
    private final Map<DayOfWeek, List<Range>> days;

    private WeeklySchedule(boolean unrestricted, Map<DayOfWeek, List<Range>> days) {
        this.unrestricted = unrestricted;
        this.days = days;
    }

    public boolean isUnrestricted() {
        return unrestricted;
    }

    /**
     * Parses the attribute value; {@code null} or blank means "inherit" and returns {@code null}.
     *
     * @throws IllegalArgumentException when the value is not a valid schedule
     */
    public static WeeklySchedule parse(String text) {
        if (text == null || text.isBlank()) return null;
        text = text.trim();
        if (text.equalsIgnoreCase("unrestricted")) return UNRESTRICTED;

        Map<DayOfWeek, List<Range>> days = new EnumMap<>(DayOfWeek.class);
        for (String part : text.split(";")) {
            part = part.trim();
            if (part.isEmpty()) continue;
            int eq = part.indexOf('=');
            if (eq <= 0) throw new IllegalArgumentException("'" + part + "' is not day=HH:mm-HH:mm");
            DayOfWeek day = DAYS.get(part.substring(0, eq).trim().toLowerCase());
            if (day == null) throw new IllegalArgumentException("'" + part.substring(0, eq) + "' is not a day");
            if (days.containsKey(day)) throw new IllegalArgumentException("Day listed twice: " + day);
            List<Range> ranges = new ArrayList<>();
            for (String range : part.substring(eq + 1).split(",")) {
                if (range.isBlank()) continue;
                ranges.add(parseRange(range.trim()));
            }
            if (!ranges.isEmpty()) days.put(day, merge(ranges));
        }
        return new WeeklySchedule(false, days);
    }

    private static Range parseRange(String text) {
        String[] parts = text.split("-");
        if (parts.length != 2) throw new IllegalArgumentException("'" + text + "' is not HH:mm-HH:mm");
        int start = minute(parts[0].trim());
        int end = minute(parts[1].trim());
        if (start >= end) throw new IllegalArgumentException("'" + text + "' does not start before it ends");
        return new Range(start, end);
    }

    private static int minute(String text) {
        if (text.equals("24:00")) return 24 * 60;
        if (!text.matches("\\d{2}:\\d{2}")) throw new IllegalArgumentException("'" + text + "' is not HH:mm");
        int hour = Integer.parseInt(text.substring(0, 2));
        int minute = Integer.parseInt(text.substring(3));
        if (hour > 23 || minute > 59) throw new IllegalArgumentException("'" + text + "' is not a time of day");
        return hour * 60 + minute;
    }

    private static List<Range> merge(List<Range> ranges) {
        List<Range> sorted = new ArrayList<>(ranges);
        sorted.sort(Comparator.comparingInt(Range::start));
        List<Range> merged = new ArrayList<>();
        for (Range r : sorted) {
            if (!merged.isEmpty() && r.start() <= merged.get(merged.size() - 1).end()) {
                Range last = merged.remove(merged.size() - 1);
                merged.add(new Range(last.start(), Math.max(last.end(), r.end())));
            } else {
                merged.add(r);
            }
        }
        return merged;
    }

    /** True when the local time (already converted to the schedule's time zone) is inside the schedule. */
    public boolean allows(ZonedDateTime localTime) {
        if (unrestricted) return true;
        int minute = localTime.getHour() * 60 + localTime.getMinute();
        List<Range> ranges = days.get(localTime.getDayOfWeek());
        return ranges != null && ranges.stream().anyMatch(r -> r.start() <= minute && minute < r.end());
    }

    /** Access whenever either schedule allows it. */
    public WeeklySchedule union(WeeklySchedule other) {
        if (unrestricted || other.unrestricted) return UNRESTRICTED;
        Map<DayOfWeek, List<Range>> result = new EnumMap<>(DayOfWeek.class);
        for (DayOfWeek day : DayOfWeek.values()) {
            List<Range> ranges = new ArrayList<>(days.getOrDefault(day, List.of()));
            ranges.addAll(other.days.getOrDefault(day, List.of()));
            if (!ranges.isEmpty()) result.put(day, merge(ranges));
        }
        return new WeeklySchedule(false, result);
    }
}
