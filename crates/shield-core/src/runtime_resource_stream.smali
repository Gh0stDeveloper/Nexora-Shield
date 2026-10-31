.class public final Ldev/nexora/shield/ResourceInputStream;
.super Ljava/io/ByteArrayInputStream;


# instance fields
.field private closed:Z


# direct methods
.method public constructor <init>([B)V
    .registers 2

    invoke-direct {p0, p1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    return-void
.end method

.method private checkOpen()V
    .registers 2

    iget-boolean v0, p0, Ldev/nexora/shield/ResourceInputStream;->closed:Z

    if-eqz v0, :cond_a

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    throw v0

    :cond_a
    return-void
.end method


# virtual methods
.method public declared-synchronized available()I
    .registers 2

    invoke-direct {p0}, Ldev/nexora/shield/ResourceInputStream;->checkOpen()V

    invoke-super {p0}, Ljava/io/ByteArrayInputStream;->available()I

    move-result v0

    return v0
.end method

.method public declared-synchronized close()V
    .registers 3

    iget-object v0, p0, Ljava/io/ByteArrayInputStream;->buf:[B

    const/4 v1, 0x0

    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([BB)V

    const/4 v0, 0x1

    iput-boolean v0, p0, Ldev/nexora/shield/ResourceInputStream;->closed:Z

    invoke-super {p0}, Ljava/io/ByteArrayInputStream;->close()V

    return-void
.end method

.method public declared-synchronized mark(I)V
    .registers 2

    invoke-direct {p0}, Ldev/nexora/shield/ResourceInputStream;->checkOpen()V

    invoke-super {p0, p1}, Ljava/io/ByteArrayInputStream;->mark(I)V

    return-void
.end method

.method public declared-synchronized read()I
    .registers 2

    invoke-direct {p0}, Ldev/nexora/shield/ResourceInputStream;->checkOpen()V

    invoke-super {p0}, Ljava/io/ByteArrayInputStream;->read()I

    move-result v0

    return v0
.end method

.method public declared-synchronized read([B)I
    .registers 3

    invoke-direct {p0}, Ldev/nexora/shield/ResourceInputStream;->checkOpen()V

    invoke-super {p0, p1}, Ljava/io/ByteArrayInputStream;->read([B)I

    move-result v0

    return v0
.end method

.method public declared-synchronized read([BII)I
    .registers 5

    invoke-direct {p0}, Ldev/nexora/shield/ResourceInputStream;->checkOpen()V

    invoke-super {p0, p1, p2, p3}, Ljava/io/ByteArrayInputStream;->read([BII)I

    move-result v0

    if-nez p3, :cond_a

    const/4 v0, 0x0

    :cond_a
    return v0
.end method

.method public declared-synchronized reset()V
    .registers 1

    invoke-direct {p0}, Ldev/nexora/shield/ResourceInputStream;->checkOpen()V

    invoke-super {p0}, Ljava/io/ByteArrayInputStream;->reset()V

    return-void
.end method

.method public declared-synchronized skip(J)J
    .registers 5

    invoke-direct {p0}, Ldev/nexora/shield/ResourceInputStream;->checkOpen()V

    const-wide/16 v0, 0x0

    cmp-long v0, p1, v0

    if-gez v0, :cond_a

    return-wide p1

    :cond_a
    invoke-super {p0, p1, p2}, Ljava/io/ByteArrayInputStream;->skip(J)J

    move-result-wide v0

    return-wide v0
.end method
