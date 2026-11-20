package main

import (
	"errors"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/labstack/echo/v5"
)

// errorMiddleware
func errorMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			err := next(c)
			if err == nil {
				return nil
			}

			// special case for validation errors
			var validationErrs validation.Errors
			if errors.As(err, &validationErrs) {
				return echo.NewHTTPError(
					http.StatusBadRequest,
					validationErrs.Error(),
				)
			}

			return echo.NewHTTPError(
				http.StatusInternalServerError,
				err.Error(),
			)
		}
	}
}
