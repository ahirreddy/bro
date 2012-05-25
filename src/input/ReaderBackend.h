// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERBACKEND_H
#define INPUT_READERBACKEND_H

#include "BroString.h"
#include "../threading/SerialTypes.h"
#include "threading/MsgThread.h"

namespace input {

class ReaderFrontend;

/**
 * Base class for reader implementation. When the input:Manager creates a
 * new input stream, it instantiates a ReaderFrontend. That then in turn
 * creates a ReaderBackend of the right type. The frontend then forwards
 * message over the backend as its methods are called.
 *
 * All of this methods must be called only from the corresponding child
 * thread (the constructor is the one exception.)
 */
class ReaderBackend : public threading::MsgThread {
public:
	/**
	 * Constructor.
	 *
	 * @param frontend The frontend reader that created this backend. The
	 * *only* purpose of this value is to be passed back via messages as
	 * a argument to callbacks. One must not otherwise access the
	 * frontend, it's running in a different thread.
	 *
	 * @param frontend pointer to the reader frontend
	 */	
	ReaderBackend(ReaderFrontend* frontend);
    	
	/**
	 * Destructor.
	 */	
	virtual ~ReaderBackend();

	/**
	 * One-time initialization of the reader to define the input source.
	 *
	 * @param arg_source A string left to the interpretation of the reader
	 * implementation; it corresponds to the value configured on the
	 * script-level for the input stream.
	 *
	 * @param num_fields The number of log fields for the stream.
	 *
	 * @param fields An array of size \a num_fields with the log fields.
	 * The methods takes ownership of the array.
	 * 
	 * @param mode the opening mode for the input source
	 *
	 * @param arg_num_fields number of fields contained in \a fields
	 *
	 * @param fields the types and names of the fields to be retrieved 
	 * from the input source
	 *
	 * @return False if an error occured.
	 */
	bool Init(string arg_source, int mode, int arg_num_fields, const threading::Field* const* fields);

	/**
	 * Finishes reading from this input stream in a regular fashion. Must not be
	 * called if an error has been indicated earlier. After calling this,
	 * no further reading from the stream can be performed
	 *
	 * @return False if an error occured.
	 */
	void Close();

	/**
	 * Force trigger an update of the input stream.
	 * The action that will be taken depends on the current read mode and the
	 * individual input backend
	 *
	 * An backend can choose to ignore this.
	 *
	 * @return False if an error occured.
	 */
	bool Update();

	/**
	 * Disables the frontend that has instantiated this backend. Once
	 * disabled,the frontend will not send any further message over.
	 */
	void DisableFrontend();	
	
protected:
    	// Methods that have to be overwritten by the individual readers
	
	/**
	 * Reader-specific intialization method. Note that data may only be 
	 * read from the input source after the Start function has been called.
	 *
	 * A reader implementation must override this method. If it returns
	 * false, it will be assumed that a fatal error has occured that
	 * prevents the reader from further operation; it will then be
	 * disabled and eventually deleted. When returning false, an
	 * implementation should also call Error() to indicate what happened.
	 */
	virtual bool DoInit(string arg_sources, int mode, int arg_num_fields, const threading::Field* const* fields) = 0;

	/**
	 * Reader-specific method implementing input finalization at
	 * termination. 
	 *
	 * A reader implementation must override this method but it can just
	 * ignore calls if an input source  must not be closed.
	 *
	 * After the method is called, the writer will be deleted. If an error occurs
	 * during shutdown, an implementation should also call Error() to indicate what
	 * happened.
	 */	
	virtual void DoClose() = 0;

	/**
	 * Reader-specific method implementing the forced update trigger
	 *
	 * A reader implementation must override this method but it can just ignore
	 * calls, if a forced update does not fit the input source or the current input
	 * reading mode.
	 *
	 * If it returns false, it will be assumed that a fatal error has occured
	 * that prevents the reader from further operation; it will then be
	 * disabled and eventually deleted. When returning false, an implementation
	 * should also call Error to indicate what happened.
	 */
	virtual bool DoUpdate() = 0;
	
	/**
	 * Returns the input source as passed into the constructor.
	 */
	const string Source() const	{ return source; }

	/**
	 * Method allowing a reader to send a specified bro event.
	 * Vals must match the values expected by the bro event.
	 *
	 * @param name name of the bro event to send
	 *
	 * @param num_vals number of entries in \a vals
	 *
	 * @param vals the values to be given to the event
	 */
	void SendEvent(const string& name, const int num_vals, threading::Value* *vals);

	// Content-sending-functions (simple mode). Including table-specific stuff that 
	// simply is not used if we have no table
	/**
	 * Method allowing a reader to send a list of values read for a specific stream
	 * back to the manager.
	 *
	 * If the stream is a table stream, the values are inserted into the table; 
	 * if it is an event stream, the event is raised.
	 *
	 * @param val list of threading::Values expected by the stream
	 */
	void Put(threading::Value* *val);

	/**
	 * Method allowing a reader to delete a specific value from a bro table.
	 *
	 * If the receiving stream is an event stream, only a removed event is raised
	 *
	 * @param val list of threading::Values expected by the stream
	 */
	void Delete(threading::Value* *val);

	/**
	 * Method allowing a reader to clear a value from a bro table.
	 *
	 * If the receiving stream is an event stream, this is ignored.
	 *
	 */
	void Clear();

	// Content-sending-functions (tracking mode): Only changed lines are propagated.
	

	/**
	 * Method allowing a reader to send a list of values read for a specific stream 
	 * back to the manager.
	 *
	 * If the stream is a table stream, the values are inserted into the table; 
	 * if it is an event stream, the event is raised.
	 *
	 * @param val list of threading::Values expected by the stream
	 */
	void SendEntry(threading::Value*  *vals);

	/**
	 * Method telling the manager, that the current list of entries sent by SendEntry 
	 * is finished.
	 * 
	 * For table streams, all entries that were not updated since the last EndCurrentSend 
	 * will be deleted, because they are no longer present in the input source
	 *
	 */
	void EndCurrentSend();

	/**
	 * Triggered by regular heartbeat messages from the main thread.
	 *
	 * This method can be overridden but once must call
	 * ReaderBackend::DoHeartbeat().
	 */
	virtual bool DoHeartbeat(double network_time, double current_time);	

	/**
	 * Utility function for Readers - convert a string into a TransportProto
	 *
	 * @param proto the transport protocol
	 */
	TransportProto StringToProto(const string &proto);		

	/**
	 * Utility function for Readers - convert a string into a Value::addr_t
	 *
	 * @param addr containing an ipv4 or ipv6 address
	 */
	threading::Value::addr_t StringToAddr(const string &addr);

private:
	// Frontend that instantiated us. This object must not be access from
	// this class, it's running in a different thread!
	ReaderFrontend* frontend;	

	string source;
    
    	bool disabled;

	// For implementing Fmt().
	char* buf;
	unsigned int buf_len;

	unsigned int num_fields;
	const threading::Field* const * fields; // raw mapping		
};

}

#endif /* INPUT_READERBACKEND_H */
