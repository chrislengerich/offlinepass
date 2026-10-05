package org.openintents.openpgp

/*
 * Vendored from the Apache-2.0 openpgp-api library
 * (Copyright 2014-2015 Dominik Schürmann) — minimal error parcelable so the
 * OpenPgpClient can read OpenKeychain's RESULT_ERROR extras.
 */
import android.os.Parcel
import android.os.Parcelable

class OpenPgpError : Parcelable {

    var errorId: Int = 0
    var message: String? = null

    constructor() {}

    constructor(errorId: Int, message: String?) {
        this.errorId = errorId
        this.message = message
    }

    constructor(source: Parcel) {
        readFromParcel(source)
    }

    fun readFromParcel(source: Parcel) {
        errorId = source.readInt()
        message = source.readString()
    }

    override fun describeContents(): Int = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(errorId)
        dest.writeString(message)
    }

    companion object {
        const val GENERIC_ERROR = 0
        const val UNSUPPORTED_ACTION = 1
        const val NO_PASSPHRASE = 2
        const val BAD_PASSPHRASE = 3
        const val USER_ID_REQUIRED = 4

        @JvmField
        val CREATOR: Parcelable.Creator<OpenPgpError?> = object : Parcelable.Creator<OpenPgpError?> {
            override fun createFromParcel(source: Parcel): OpenPgpError = OpenPgpError(source)
            override fun newArray(size: Int): Array<OpenPgpError?> = arrayOfNulls(size)
        }
    }
}
