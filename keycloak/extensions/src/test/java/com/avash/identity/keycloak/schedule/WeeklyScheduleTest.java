package com.avash.identity.keycloak.schedule;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

/** Same cases as the gateway's AccessScheduleTests: both implementations read the same attribute. */
class WeeklyScheduleTest {

    // Saturday 2026-10-31 in Tehran.
    private static ZonedDateTime saturdayAt(int hour, int minute) {
        return ZonedDateTime.of(2026, 10, 31, hour, minute, 0, 0, ZoneId.of("Asia/Tehran"));
    }

    @Test
    void emptyMeansInherit() {
        assertNull(WeeklySchedule.parse(null));
        assertNull(WeeklySchedule.parse("  "));
    }

    @Test
    void rangesHaveExclusiveEnds() {
        WeeklySchedule office = WeeklySchedule.parse("sat=08:00-16:00");
        assertTrue(office.allows(saturdayAt(8, 0)));
        assertTrue(office.allows(saturdayAt(15, 59)));
        assertFalse(office.allows(saturdayAt(16, 0)));
        assertFalse(office.allows(saturdayAt(7, 59)));
        assertFalse(office.allows(saturdayAt(10, 0).plusDays(1)));
    }

    @Test
    void anEmptyDayListDeniesEverything() {
        assertFalse(WeeklySchedule.parse("sat=").allows(saturdayAt(10, 0)));
    }

    @Test
    void unionAddsRangesAndUnrestrictedWins() {
        WeeklySchedule morning = WeeklySchedule.parse("sat=08:00-12:00");
        WeeklySchedule evening = WeeklySchedule.parse("SAT=18:00-24:00");
        WeeklySchedule both = morning.union(evening);
        assertTrue(both.allows(saturdayAt(9, 0)));
        assertTrue(both.allows(saturdayAt(23, 30)));
        assertFalse(both.allows(saturdayAt(14, 0)));
        assertTrue(morning.union(WeeklySchedule.UNRESTRICTED).isUnrestricted());
    }

    @ParameterizedTest
    @ValueSource(strings = {"sat=16:00-08:00", "sat=8-16", "xyz=08:00-16:00", "sat=08:00-16:00;sat=17:00-18:00", "sat=24:30-25:00"})
    void invalidSchedulesAreRejected(String text) {
        assertThrows(IllegalArgumentException.class, () -> WeeklySchedule.parse(text));
    }
}
