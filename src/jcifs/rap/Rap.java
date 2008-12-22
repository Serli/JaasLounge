package jcifs.smb;

import java.io.IOException;

import java.net.MalformedURLException;

import jcifs.Config;

import jcifs.rap.Operation;

public abstract class Rap {

    protected static final String DEFAULT_TARGET =
            Config.getProperty("jcifs.smb.client.domain");

    protected SmbFile target;

    public Rap() {
        this(null, null);
    }

    public Rap(String target) {
        this(target, null);
    }

    public Rap(NtlmPasswordAuthentication auth) {
        this(null, auth);
    }

    public Rap(String target, NtlmPasswordAuthentication auth) {
        try {
            if (target == null) target = DEFAULT_TARGET;
            this.target = (auth != null) ? new SmbFile("smb://", target, auth) :
                    new SmbFile("smb://", target);
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("Invalid target: " + target);
        }
    }

    public Rap(SmbFile target) {
        if (target == null) throw new NullPointerException("Null target.");
        this.target = target;
    }

    protected int call(Operation operation) throws IOException {
        RapResponse response = new RapResponse(operation);
        target.send/* jerome removed Transaction */(new RapRequest(operation), response);
        return response.status;
    }

}
