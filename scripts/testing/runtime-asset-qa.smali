
.method public static assertAsset(Landroid/content/res/AssetManager;Ljava/lang/String;Ljava/lang/String;I)V
    .registers 10
    const/4 v5, 0x1
    if-nez p3, :mode
    invoke-virtual {p0, p1}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;
    move-result-object v0
    goto :opened
    :mode
    const/4 v0, 0x1
    invoke-virtual {p0, p1, v0}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;I)Ljava/io/InputStream;
    move-result-object v0
    :opened
    const/4 v5, 0x2
    invoke-virtual {v0}, Ljava/io/InputStream;->markSupported()Z
    move-result v1
    if-eqz v1, :failed
    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Ljava/io/InputStream;->mark(I)V
    invoke-virtual {v0}, Ljava/io/InputStream;->read()I
    move-result v1
    invoke-virtual {v0}, Ljava/io/InputStream;->reset()V
    invoke-virtual {v0}, Ljava/io/InputStream;->read()I
    move-result v2
    if-ne v1, v2, :failed
    invoke-virtual {v0}, Ljava/io/InputStream;->reset()V
    const-wide/16 v1, -0x1
    invoke-virtual {v0, v1, v2}, Ljava/io/InputStream;->skip(J)J
    move-result-wide v3
    cmp-long v1, v1, v3
    if-nez v1, :failed
    const/4 v5, 0x3
    const-string v1, "SHA-256"
    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v1
    const/16 v2, 0x1000
    new-array v2, v2, [B
    :read
    invoke-virtual {v0, v2}, Ljava/io/InputStream;->read([B)I
    move-result v3
    const/4 v4, -0x1
    if-eq v3, v4, :eof
    if-lez v3, :failed
    const/4 v4, 0x0
    invoke-virtual {v1, v2, v4, v3}, Ljava/security/MessageDigest;->update([BII)V
    goto :read
    :eof
    const/4 v5, 0x4
    invoke-virtual {v0}, Ljava/io/InputStream;->available()I
    move-result v3
    if-nez v3, :failed
    const/4 v3, 0x0
    invoke-virtual {v0, v2, v3, v3}, Ljava/io/InputStream;->read([BII)I
    move-result v3
    if-nez v3, :failed
    invoke-virtual {v0}, Ljava/io/InputStream;->read()I
    move-result v3
    const/4 v4, -0x1
    if-ne v3, v4, :failed
    const/4 v5, 0x5
    invoke-virtual {v1}, Ljava/security/MessageDigest;->digest()[B
    move-result-object v1
    const/4 v2, 0x2
    invoke-static {v1, v2}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;
    move-result-object v1
    invoke-virtual {p2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1
    if-eqz v1, :failed
    const/4 v5, 0x6
    invoke-virtual {v0}, Ljava/io/InputStream;->close()V
    :closed_start
    invoke-virtual {v0}, Ljava/io/InputStream;->read()I
    :closed_end
    goto :failed
    .catch Ljava/lang/IllegalStateException; {:closed_start .. :closed_end} :closed
    :closed
    move-exception v0
    return-void
    :failed
    const-string v0, "NexoraRuntime"
    invoke-static {v5}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;
    move-result-object v1
    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    new-instance v0, Ljava/lang/AssertionError;
    invoke-direct {v0}, Ljava/lang/AssertionError;-><init>()V
    throw v0
.end method
