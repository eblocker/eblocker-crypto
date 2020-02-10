/*
 * Copyright 2020 eBlocker Open Source UG (haftungsbeschraenkt)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the EUPL
 * (the "License"); You may not use this work except in compliance with
 * the License. You may obtain a copy of the License at:
 *
 *   https://joinup.ec.europa.eu/page/eupl-text-11-12
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package org.eblocker.crypto.json;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;

public class TestEntity {

    @JsonProperty("what")
    private final String what;

    @JsonProperty("howmuch")
    private final int howmuch;

    @JsonProperty("when")
    private final Date when;

    public TestEntity(@JsonProperty("what") String what, @JsonProperty("howmuch") int howmuch, @JsonProperty("when") Date when) {
        this.what = what;
        this.howmuch = howmuch;
        this.when = when;
    }

    public String getWhat() {
        return what;
    }

    public int getHowmuch() {
        return howmuch;
    }

    public Date getWhen() {
        return when;
    }
}
