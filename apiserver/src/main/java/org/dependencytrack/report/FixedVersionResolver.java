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

import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.Comparator;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import io.github.nscuro.versatile.spi.InvalidVersionException;
import io.github.nscuro.versatile.spi.Version;
import io.github.nscuro.versatile.version.KnownVersioningSchemes;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.util.PurlUtil;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * Derives the first fixed version of a finding from the vulnerable version ranges
 * associated with its vulnerability.
 * <p>
 * A range contributes a fixed version when its identity (purl or CPE) matches the
 * affected component and the component version falls inside the range. Ranges that
 * only end with an including bound are skipped, as the version after an inclusive
 * last-vulnerable version cannot be derived from the range alone.
 */
public final class FixedVersionResolver {

    public @Nullable String resolve(
            final @Nullable String componentPurl,
            final @Nullable String componentCpe,
            final @Nullable String componentVersion,
            final List<VulnerableSoftware> vulnerableSoftware) {
        if (componentVersion == null) {
            return null;
        }

        final PackageURL purl = parsePurl(componentPurl);
        final String scheme = schemeOf(purl);
        String bestFixedVersion = null;
        for (final VulnerableSoftware vs : vulnerableSoftware) {
            if (!matchesIdentity(vs, purl, componentCpe)) {
                continue;
            }
            // Ranges without an exclusive end bound can never contribute a
            // fixed version; skip them before the containment check parses anything.
            final String endExcluding = vs.getVersionEndExcluding();
            if (endExcluding == null) {
                continue;
            }
            if (!containsVersion(vs, componentVersion, scheme)) {
                continue;
            }
            if (bestFixedVersion == null || isGreater(endExcluding, bestFixedVersion, scheme)) {
                bestFixedVersion = endExcluding;
            }
        }
        return bestFixedVersion;
    }

    private static boolean matchesIdentity(
            final VulnerableSoftware vs,
            final @Nullable PackageURL componentPurl,
            final @Nullable String componentCpe) {
        if (vs.getPurlType() != null) {
            return matchesPurl(vs, componentPurl);
        }
        if (vs.getCpe23() != null) {
            return matchesCpe(vs, componentCpe);
        }
        return false;
    }

    private static boolean matchesPurl(final VulnerableSoftware vs, final @Nullable PackageURL componentPurl) {
        if (componentPurl == null) {
            return false;
        }
        return vs.getPurlType().equals(componentPurl.getType())
                && nullableEquals(vs.getPurlNamespace(), componentPurl.getNamespace())
                && nullableEquals(vs.getPurlName(), componentPurl.getName());
    }

    private static @Nullable PackageURL parsePurl(final @Nullable String purl) {
        return PurlUtil.silentPurl(purl);
    }

    private static boolean matchesCpe(final VulnerableSoftware vs, final @Nullable String componentCpe) {
        if (componentCpe == null) {
            return false;
        }
        final String[] componentParts = componentCpe.split(":");
        final String[] rangeParts = vs.getCpe23().split(":");
        if (componentParts.length < 5 || rangeParts.length < 5) {
            return false;
        }
        return componentParts[2].equals(rangeParts[2])
                && componentParts[3].equals(rangeParts[3])
                && componentParts[4].equals(rangeParts[4]);
    }

    private static boolean containsVersion(final VulnerableSoftware vs, final String version, final String scheme) {
        final var builder = Vers.builder(scheme);
        if (vs.getVersionStartIncluding() != null) {
            builder.withConstraint(Comparator.GREATER_THAN_OR_EQUAL, vs.getVersionStartIncluding());
        }
        if (vs.getVersionStartExcluding() != null) {
            builder.withConstraint(Comparator.GREATER_THAN, vs.getVersionStartExcluding());
        }
        if (vs.getVersionEndIncluding() != null) {
            builder.withConstraint(Comparator.LESS_THAN_OR_EQUAL, vs.getVersionEndIncluding());
        }
        if (vs.getVersionEndExcluding() != null) {
            builder.withConstraint(Comparator.LESS_THAN, vs.getVersionEndExcluding());
        }
        if (!builder.hasConstraints()) {
            return false;
        }
        try {
            return builder.build().contains(version);
        } catch (final VersException | InvalidVersionException e) {
            if (KnownVersioningSchemes.SCHEME_GENERIC.equals(scheme)) {
                return false;
            }
            // The range or version does not comply with the ecosystem's scheme;
            // retry with the scheme-agnostic comparator.
            return containsVersion(vs, version, KnownVersioningSchemes.SCHEME_GENERIC);
        }
    }

    private static boolean isGreater(final String a, final String b, final String scheme) {
        try {
            return parseVersion(scheme, a).compareTo(parseVersion(scheme, b)) > 0;
        } catch (final VersException | InvalidVersionException e) {
            if (KnownVersioningSchemes.SCHEME_GENERIC.equals(scheme)) {
                return false;
            }
            return isGreater(a, b, KnownVersioningSchemes.SCHEME_GENERIC);
        }
    }

    private static Version parseVersion(final String scheme, final String version)
            throws VersException, InvalidVersionException {
        return Vers.builder(scheme)
                .withConstraint(Comparator.EQUAL, version)
                .build()
                .constraints()
                .getFirst()
                .version();
    }

    private static String schemeOf(final @Nullable PackageURL componentPurl) {
        if (componentPurl == null) {
            return KnownVersioningSchemes.SCHEME_GENERIC;
        }
        return KnownVersioningSchemes.fromPurlType(componentPurl.getType())
                .orElse(KnownVersioningSchemes.SCHEME_GENERIC);
    }

    private static boolean nullableEquals(final @Nullable String a, final @Nullable String b) {
        return a == null ? b == null : a.equals(b);
    }
}
