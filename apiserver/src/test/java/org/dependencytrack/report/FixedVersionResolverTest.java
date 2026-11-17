/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.report;

import org.dependencytrack.model.VulnerableSoftware;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FixedVersionResolverTest {

    private final FixedVersionResolver resolver = new FixedVersionResolver();

    @Test
    void resolvesEndExcludingOfPurlRangeContainingVersion() {
        final VulnerableSoftware range = purlRange("maven", "com.example", "lib", "1.0.0", null, null, "2.0.0");

        assertThat(resolver.resolve("pkg:maven/com.example/lib@1.5.0", null, "1.5.0", List.of(range)))
                .isEqualTo("2.0.0");
    }

    @Test
    void returnsNullWhenVersionOutsidePurlRange() {
        final VulnerableSoftware range = purlRange("maven", "com.example", "lib", "1.0.0", null, null, "2.0.0");

        assertThat(resolver.resolve("pkg:maven/com.example/lib@2.5.0", null, "2.5.0", List.of(range)))
                .isNull();
        assertThat(resolver.resolve("pkg:maven/com.example/lib@0.9.0", null, "0.9.0", List.of(range)))
                .isNull();
    }

    @Test
    void returnsNullWhenPurlIdentityDoesNotMatch() {
        final VulnerableSoftware range = purlRange("maven", "com.example", "other-lib", null, null, null, "2.0.0");

        assertThat(resolver.resolve("pkg:maven/com.example/lib@1.5.0", null, "1.5.0", List.of(range)))
                .isNull();
    }

    @Test
    void resolvesEndExcludingOfCpeRangeContainingVersion() {
        final VulnerableSoftware range = cpeRange("cpe:2.3:a:mit:kerberos_5:*:*:*:*:*:*:*:*", null, null, "1.22.0");

        assertThat(resolver.resolve(null, "cpe:2.3:a:mit:kerberos_5:1.21.2:*:*:*:*:*:*:*", "1.21.2", List.of(range)))
                .isEqualTo("1.22.0");
    }

    @Test
    void returnsNullForRangeWithOnlyEndIncluding() {
        final VulnerableSoftware range = purlRange("maven", "com.example", "lib", null, null, "2.0.0", null);

        assertThat(resolver.resolve("pkg:maven/com.example/lib@1.5.0", null, "1.5.0", List.of(range)))
                .isNull();
    }

    @Test
    void picksHighestEndExcludingAmongCoveringRanges() {
        final VulnerableSoftware lower = purlRange("maven", "com.example", "lib", "1.0.0", null, null, "1.6.0");
        final VulnerableSoftware higher = purlRange("maven", "com.example", "lib", "1.0.0", null, null, "2.0.0");

        assertThat(resolver.resolve("pkg:maven/com.example/lib@1.5.0", null, "1.5.0", List.of(lower, higher)))
                .isEqualTo("2.0.0");
    }

    @Test
    void comparesMultiPartVersionsNumerically() {
        final VulnerableSoftware range = purlRange("maven", "com.example", "lib", null, null, null, "1.10.0");

        // 1.9.0 < 1.10.0 numerically, although lexicographically "9" > "10".
        assertThat(resolver.resolve("pkg:maven/com.example/lib@1.9.0", null, "1.9.0", List.of(range)))
                .isEqualTo("1.10.0");
        // 1.10.5 is beyond the range end.
        assertThat(resolver.resolve("pkg:maven/com.example/lib@1.10.5", null, "1.10.5", List.of(range)))
                .isNull();
    }

    @Test
    void returnsNullWhenComponentVersionIsUnknown() {
        final VulnerableSoftware range = purlRange("maven", "com.example", "lib", "1.0.0", null, null, "2.0.0");

        assertThat(resolver.resolve("pkg:maven/com.example/lib", null, null, List.of(range)))
                .isNull();
    }

    @Test
    void ordersPrereleasesBelowTheirRelease() {
        // semver/Maven ordering: 2.0.0-rc1 < 2.0.0. A range ending at 2.0.0-rc1 (exclusive)
        // does not cover the released 2.0.0, so no fixed version can be derived.
        final VulnerableSoftware range = purlRange("maven", "com.example", "lib", null, null, null, "2.0.0-rc1");

        assertThat(resolver.resolve("pkg:maven/com.example/lib@2.0.0", null, "2.0.0", List.of(range)))
                .isNull();
        assertThat(resolver.resolve("pkg:maven/com.example/lib@1.9.0", null, "1.9.0", List.of(range)))
                .isEqualTo("2.0.0-rc1");
    }

    private static VulnerableSoftware purlRange(
            final String type,
            final String namespace,
            final String name,
            final String startIncluding,
            final String startExcluding,
            final String endIncluding,
            final String endExcluding) {
        final var vs = new VulnerableSoftware();
        vs.setPurlType(type);
        vs.setPurlNamespace(namespace);
        vs.setPurlName(name);
        vs.setVersionStartIncluding(startIncluding);
        vs.setVersionStartExcluding(startExcluding);
        vs.setVersionEndIncluding(endIncluding);
        vs.setVersionEndExcluding(endExcluding);
        return vs;
    }

    private static VulnerableSoftware cpeRange(
            final String cpe23, final String startIncluding, final String startExcluding, final String endExcluding) {
        final var vs = new VulnerableSoftware();
        vs.setCpe23(cpe23);
        vs.setVersionStartIncluding(startIncluding);
        vs.setVersionStartExcluding(startExcluding);
        vs.setVersionEndExcluding(endExcluding);
        return vs;
    }
}
