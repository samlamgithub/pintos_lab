/*
 * fixed-point.h

 *
 *  Created on: 4 Feb 2015
 *      Author: yg3113
 */


#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

#define P 17
#define Q 14
#define F (1<<Q)

#define convert_to_fixed(n) (n*F)
#define convert_to_int_zero_rounding(x) (x/F)
#define convert_to_int_nearest_rounding(x) ((x>=0) ? ((x+F/2)/F): ((x-F/2)/F))
#define add_fixed(x, y) (x+y)
#define subtract_fixed(x, y) (x-y)
#define add_fixed_to_int(x, n) (x+n*F)
#define subtract_int_from_fixed(n, x) (x - n *F)
#define mult_fixed(x, y) (((int64_t) x) * y / F)
#define mult_fixed_and_int(x, n) (x*n)
#define div_fixed(x, y) (((int64_t) x) * F / y)
#define dic_fixed_by_int(x, n) (x/n)


#endif /* FIXED_POINT_H_ */
