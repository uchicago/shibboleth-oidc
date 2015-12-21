package net.shibboleth.idp.oidc.token;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.collection.Pair;
import org.opensaml.storage.StorageCapabilities;
import org.opensaml.storage.StorageRecord;
import org.opensaml.storage.StorageSerializer;
import org.opensaml.storage.StorageService;
import org.opensaml.storage.VersionMismatchException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;

public class DefaultOpenIdConnectStorageService implements OpenIdConnectStorageService {

    private StorageService storageService;

    public void setStorageService(final StorageService storageService) {
        this.storageService = storageService;
    }

    @Nonnull
    @Override
    public StorageCapabilities getCapabilities() {
        return this.storageService.getCapabilities();
    }

    @Override
    public boolean create(@Nonnull @NotEmpty final String s, @Nonnull @NotEmpty final String s1, @Nonnull @NotEmpty final String s2, @Nullable @Positive final Long aLong) throws IOException {
        return this.storageService.create(s, s1, s2, aLong);
    }

    @Override
    public boolean create(@Nonnull @NotEmpty final String s, @Nonnull @NotEmpty final String s1, @Nonnull final Object o,
                          @Nonnull final StorageSerializer storageSerializer, @Nullable @Positive final Long aLong) throws IOException {
        return this.storageService.create(s, s1, o, storageSerializer, aLong);
    }

    @Override
    public boolean create(@Nonnull final Object o) throws IOException {
        return this.storageService.create(o);
    }

    @Nullable
    @Override
    public StorageRecord read(@Nonnull @NotEmpty final String s, @Nonnull @NotEmpty final String s1) throws IOException {
        return this.storageService.read(s, s1);
    }

    @Nullable
    @Override
    public Object read(@Nonnull final Object o) throws IOException {
        return this.storageService.read(o);
    }

    @Nonnull
    @Override
    public Pair<Long, StorageRecord> read(@Nonnull @NotEmpty final String s, @Nonnull @NotEmpty final String s1, @Positive final long l)
            throws IOException {
        return this.storageService.read(s, s1, l);
    }

    @Override
    public boolean update(@Nonnull @NotEmpty final String s, @Nonnull @NotEmpty final String s1, @Nonnull @NotEmpty final String s2,
                          @Nullable @Positive final Long aLong) throws IOException {
        return this.storageService.update(s, s1, s2, aLong);
    }

    @Nullable
    @Override
    public Long updateWithVersion(@Positive final long l, @Nonnull @NotEmpty final String s, @Nonnull @NotEmpty final String s1,
                                  @Nonnull @NotEmpty final String s2, @Nullable @Positive final Long aLong)
            throws IOException, VersionMismatchException {
        return this.storageService.updateWithVersion(l, s1, s1, s2, aLong);
    }

    @Override
    public boolean update(@Nonnull @NotEmpty final String s, @Nonnull @NotEmpty final String s1, @Nonnull final Object o,
                          @Nonnull final StorageSerializer storageSerializer, @Nullable @Positive final Long aLong) throws IOException {
        return this.storageService.update(s, s1, o, storageSerializer, aLong);
    }

    @Nullable
    @Override
    public Long updateWithVersion(@Positive final long l, @Nonnull @NotEmpty final String s, @Nonnull @NotEmpty final String s1,
                                  @Nonnull final Object o, @Nonnull final StorageSerializer storageSerializer,
                                  @Nullable @Positive final Long aLong) throws IOException, VersionMismatchException {
        return this.storageService.updateWithVersion(l, s, s1, o, storageSerializer, aLong);
    }

    @Override
    public boolean update(@Nonnull final Object o) throws IOException {
        return this.storageService.update(o);
    }

    @Nullable
    @Override
    public Long updateWithVersion(@Positive final long l, @Nonnull final Object o) throws IOException, VersionMismatchException {
        return this.storageService.updateWithVersion(l, o);
    }

    @Override
    public boolean updateExpiration(@Nonnull @NotEmpty final String s, @Nonnull @NotEmpty final String s1,
                                    @Nullable @Positive final Long aLong) throws IOException {
        return this.storageService.updateExpiration(s, s1, aLong);
    }

    @Override
    public boolean updateExpiration(@Nonnull final Object o) throws IOException {
        return this.storageService.updateExpiration(o);
    }

    @Override
    public boolean delete(@Nonnull @NotEmpty final String s, @Nonnull @NotEmpty final String s1) throws IOException {
        return this.storageService.delete(s, s1);
    }

    @Override
    public boolean deleteWithVersion(@Positive final long l, @Nonnull @NotEmpty final String s,
                                     @Nonnull @NotEmpty final String s1) throws IOException, VersionMismatchException {
        return this.storageService.deleteWithVersion(l, s, s1);
    }

    @Override
    public boolean delete(@Nonnull final Object o) throws IOException {
        return this.storageService.delete(o);
    }

    @Override
    public boolean deleteWithVersion(@Positive final long l, @Nonnull final Object o) throws IOException, VersionMismatchException {
        return this.storageService.deleteWithVersion(l, o);
    }

    @Override
    public void reap(@Nonnull @NotEmpty final String s) throws IOException {
        this.storageService.reap(s);
    }

    @Override
    public void updateContextExpiration(@Nonnull @NotEmpty final String s, @Nullable final Long aLong) throws IOException {
        this.storageService.updateContextExpiration(s, aLong);
    }

    @Override
    public void deleteContext(@Nonnull @NotEmpty final String s) throws IOException {
        this.storageService.deleteContext(s);
    }

    @Nullable
    @Override
    public String getId() {
        return this.storageService.getId();
    }
}
