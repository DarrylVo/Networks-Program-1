/*
 * trace.hpp
 *
 *  Created on: Apr 1, 2016
 *      Author: darryl
 */

#ifndef SRC_TRACE_HPP_
#define SRC_TRACE_HPP_

typedef struct ethernet {
	unsigned char src[6];
	unsigned char dest[6];
	unsigned char type[2];
};

void getethernet(const u_char *pktdata, ethernet *e);

void printethernet(ethernet *e);



#endif /* SRC_TRACE_HPP_ */
